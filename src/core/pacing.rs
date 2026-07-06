//! LiveCC pacing (docs/spec/transmission.md §3.3): the send-interval
//! formula, the sender input-rate estimator behind [`Bandwidth::Estimated`],
//! and the `SendTimeDiff` lateness-credit schedule. Pure structs in the
//! sans-I/O style — every event carries the caller's `now`, nothing here
//! reads a clock. All libsrt citations refer to the v1.4.4 tree.

use std::time::{
    Duration,
    Instant,
};

use crate::options::Bandwidth;

/// `BW_INFINITE` (common.h:280): 1 Gbps in bytes/s.
pub(crate) const BW_INFINITE: u64 = 125_000_000;
/// `CPacket::SRT_DATA_HDR_SIZE` = 28 (UDP/IPv4) + 16 (SRT header),
/// packet.h:404-410. Charged per packet on top of the payload: pacing
/// budgets the *wire* rate, not the payload rate.
pub(crate) const DATA_HDR_SIZE: u64 = 44;
/// libsrt live default SRTO_PAYLOADSIZE (SRT_LIVE_DEF_PLSIZE): the
/// AvgPayloadSize IIR starts here, capped by the negotiated max payload.
const LIVE_DEF_PAYLOAD: u64 = 1316;
/// INPUTRATE_FAST_START_US / INPUTRATE_RUNNING_US / INPUTRATE_MAX_PACKETS
/// (buffer.h:204-207). INPUTRATE_INITIAL_BYTESPS == BW_INFINITE is
/// expressed as the `unwrap_or` in [`InputRateEstimator::ceiling_input`].
const INPUTRATE_FAST_START: Duration = Duration::from_millis(500);
const INPUTRATE_RUNNING: Duration = Duration::from_secs(1);
const INPUTRATE_MAX_PACKETS: u64 = 2000;

/// Integer IIR smoother (transmission.md §1.4, libsrt utilities.h
/// `avg_iir`): `(old·(N-1) + sample) / N`. Non-wrapping for our operand
/// sizes (≤ 1456·127).
fn avg_iir<const N: u64>(old: u64, sample: u64) -> u64 {
    (old * (N - 1) + sample) / N
}

/// `CUDT::withOverhead` (core.h:656-659): `base·(100+pct)/100`, integer
/// truncation. `saturating_mul` is behavior-identical hardening for every
/// representable real-world value (libsrt would overflow signed — UB).
pub(crate) fn with_overhead(base: u64, pct: u8) -> u64 {
    base.saturating_mul(100 + pct as u64) / 100
}

/// Sender input-rate estimator — `CSndBuffer::updateInputRate`
/// (buffer.cpp:299-333). Fed exclusively where the application submits
/// payloads (payload bytes, no headers; retransmissions never counted);
/// the closed-window rate charges +44 bytes/packet once, at close.
struct InputRateEstimator {
    /// Window length (`m_InRatePeriod`): fast-start 500 ms until the
    /// first close, 1 s from then on.
    period: Duration,
    /// `m_tsInRateStartTime`; `None` = unstamped.
    window_start: Option<Instant>,
    pkts: u64,
    /// Window payload bytes, headers excluded until close.
    bytes: u64,
    /// Last closed-window rate, bytes/s; `None` until the first close.
    /// Never recomputed on silence — a stale value persists forever
    /// (libsrt behavior; `min_bytes_per_sec` is the operator's floor).
    rate: Option<u64>,
}

impl InputRateEstimator {
    fn new() -> Self {
        InputRateEstimator {
            period: INPUTRATE_FAST_START,
            window_start: None,
            pkts: 0,
            bytes: 0,
            rate: None,
        }
    }

    fn on_input(&mut self, now: Instant, payload_len: usize) {
        // The first sample after construction only stamps the window; its
        // bytes are NOT counted (buffer.cpp:305-309).
        let Some(start) = self.window_start else {
            self.window_start = Some(now);
            return;
        };
        self.pkts += 1;
        self.bytes += payload_len as u64;
        // Fast-start early close, strict `>` (buffer.cpp:315).
        let early = self.period < INPUTRATE_RUNNING && self.pkts > INPUTRATE_MAX_PACKETS;
        // libsrt compares the whole-µs-truncated elapsed (count_microseconds,
        // buffer.cpp:317-318), so a window effectively closes only once true
        // elapsed reaches period + 1 µs; the close division uses the same
        // truncated value.
        let elapsed_us = now.saturating_duration_since(start).as_micros() as u64;
        // Close on strict `elapsed > period` (buffer.cpp:318). The ≥ 1 µs
        // guard is ours: the establish-time pending_send flush pushes up
        // to 8192 packets with one identical `now` (mod.rs), tripping the
        // >2000 early close at elapsed == 0 — libsrt would divide by
        // zero. When the guard suppresses a close, counters keep
        // accumulating and the next distinct-instant push closes normally.
        if (early || elapsed_us > self.period.as_micros() as u64) && elapsed_us >= 1 {
            // Header cost charged once per window, at close (buffer.cpp:321).
            let total = self.bytes + self.pkts * DATA_HDR_SIZE;
            self.rate = Some(total.saturating_mul(1_000_000) / elapsed_us);
            self.pkts = 0;
            self.bytes = 0;
            self.window_start = Some(now);
            self.period = INPUTRATE_RUNNING;
        }
    }

    /// The value the ceiling math consumes (libsrt `getInputRate()`):
    /// BW_INFINITE until the first close — the unpaced fast-start grace
    /// (INPUTRATE_INITIAL_BYTESPS, buffer.h:207).
    fn ceiling_input(&self) -> u64 {
        self.rate.unwrap_or(BW_INFINITE)
    }

    /// The stats value: 0 until the first close — never report the
    /// fictitious 125 MB/s grace value to operators.
    fn measured(&self) -> u64 {
        self.rate.unwrap_or(0)
    }
}

/// LiveCC pacer: effective ceiling, avg-payload IIR, whole-µs send
/// interval and the `SendTimeDiff` credit schedule (congctl.cpp:173-180,
/// core.cpp:8966-9252). One per `Sender`; structurally absent for
/// [`Bandwidth::Unlimited`] (spec-marked divergence: libsrt's MAXBW = -1
/// default still gates at BW_INFINITE, a ~10.9 µs period below any
/// achievable timer resolution).
pub(crate) struct Pacer {
    mode: PacerMode,
    /// Current effective ceiling (LiveCC `m_llSndMaxBW`), bytes/s. Never
    /// 0: validation forbids zero rates and `refresh` keeps the previous
    /// ceiling on a zero estimate.
    max_bw: u64,
    /// avg_iir<128> over emitted payload lengths, rexmits included
    /// (transmission.md §3.3); init min(1316, max_payload).
    avg_payload: u64,
    /// PktSndPeriod truncated to whole µs: libsrt copies the double
    /// `m_dPktSndPeriod` into `m_tdSendInterval` through an `(int64_t)`
    /// cast (core.cpp:7371-7379), and the double holds no cross-event
    /// state — one truncated field is exactly equivalent.
    period: Duration,
    /// `m_tsNextSendTime`; `None` == libsrt `is_zero()` — gate disarmed,
    /// the next packet goes out immediately. Exposed to the `Sender`
    /// gate, which reads it and accrues entry lateness into `credit`.
    pub(crate) next_send_time: Option<Instant>,
    /// `m_tdSendTimeDiff` — lateness credit spent to send back-to-back.
    pub(crate) credit: Duration,
}

enum PacerMode {
    /// `Max` / `Input`: ceiling fixed at construction.
    Fixed,
    /// `Estimated`: ceiling re-derived from the estimator on `refresh`.
    Estimated {
        est: InputRateEstimator,
        min: u64,
        overhead_pct: u8,
    },
}

impl Pacer {
    /// `bw` must have passed `Bandwidth::validate`.
    pub(crate) fn new(bw: &Bandwidth, max_payload: usize) -> Option<Pacer> {
        let (mode, max_bw) = match *bw {
            // No pacer at all: zero cost, default behavior structurally
            // untouched (the spec-marked divergence above).
            Bandwidth::Unlimited => return None,
            Bandwidth::Max { bytes_per_sec } => (PacerMode::Fixed, bytes_per_sec),
            // Ceiling computed once: options are immutable post-connect
            // (libsrt recomputes only on runtime option changes we lack).
            Bandwidth::Input { bytes_per_sec, overhead_pct } => {
                (PacerMode::Fixed, with_overhead(bytes_per_sec, overhead_pct))
            }
            // Parity with `updateBandwidth(0, 0)` at TEV_INIT: LiveCC
            // keeps its ctor BW_INFINITE ceiling; the overheaded estimate
            // first lands at the first refresh event.
            Bandwidth::Estimated { min_bytes_per_sec, overhead_pct } => (
                PacerMode::Estimated {
                    est: InputRateEstimator::new(),
                    min: min_bytes_per_sec,
                    overhead_pct,
                },
                BW_INFINITE,
            ),
        };
        let mut pacer = Pacer {
            mode,
            max_bw,
            avg_payload: LIVE_DEF_PAYLOAD.min(max_payload as u64),
            period: Duration::ZERO,
            // Zero `m_tsNextSendTime`: the first packet after establish
            // goes out immediately.
            next_send_time: None,
            credit: Duration::ZERO,
        };
        pacer.recompute_period();
        Some(pacer)
    }

    /// LiveCC `updatePktSndPeriod` (congctl.cpp:173-180): f64 math,
    /// truncated to whole µs by the interval copy-out. A ceiling large
    /// enough to truncate the period to 0 degenerates to "always
    /// immediate", same as libsrt.
    fn recompute_period(&mut self) {
        // `max_bw` is never 0 (see field doc); `.max(1)` is defense only.
        self.period = Duration::from_micros(
            (1_000_000.0 * (self.avg_payload + DATA_HDR_SIZE) as f64
                / self.max_bw.max(1) as f64) as u64,
        );
    }

    /// The application submitted a payload — sampled at `Sender::push`,
    /// pre-encryption (AES-CTR does not expand, so it equals the wire
    /// payload length). Retransmissions never reach this, matching libsrt
    /// `addBuffer` as the sole feed point.
    pub(crate) fn on_input(&mut self, now: Instant, payload_len: usize) {
        if let PacerMode::Estimated { est, .. } = &mut self.mode {
            est.on_input(now, payload_len);
        }
    }

    /// Rate-event recompute — the updateCC periodic block and LiveCC
    /// `updateBandwidth` merged (core.cpp:7344-7363, congctl.cpp:182-219).
    /// Called on full ACK / NAK / timer tick; never on send (libsrt
    /// excludes TEV_SEND from the interval copy-out).
    pub(crate) fn refresh(&mut self) {
        if let PacerMode::Estimated { est, min, overhead_pct } = &self.mode {
            let bw = with_overhead((*min).max(est.ceiling_input()), *overhead_pct);
            // LiveCC's `if (bw == 0) return;` (congctl.cpp:209-212): a
            // degenerate window with min == 0 keeps the previous ceiling.
            if bw > 0 {
                self.max_bw = bw;
            }
        }
        // Fixed ceilings still recompute: the period picks up avg-payload
        // IIR drift (libsrt re-derives the ceiling only in the auto path).
        self.recompute_period();
    }

    /// A data packet was emitted (new or rexmit) — TEV_SEND plus the
    /// packData scheduling tail (core.cpp:9198, 9221-9248).
    pub(crate) fn on_send(&mut self, now: Instant, payload_len: usize, probe: bool) {
        // Every data packet feeds the payload IIR, rexmits included; the
        // period only picks it up at the next `refresh`.
        self.avg_payload = avg_iir::<128>(self.avg_payload, payload_len as u64);
        if probe {
            // Probe pair (`seq & 0xF == 0`, NEW packets only): the next
            // send is due at `now`, credit untouched (core.cpp:9221-9230)
            // — the peer's capacity estimator needs the pair back-to-back.
            self.next_send_time = Some(now);
        } else if self.credit >= self.period {
            self.next_send_time = Some(now);
            self.credit -= self.period;
        } else {
            self.next_send_time = Some(now + (self.period - self.credit));
            self.credit = Duration::ZERO;
        }
    }

    /// A due poll found nothing sendable (idle or window-blocked) — the
    /// packData reset (core.cpp:9106-9117): credit never survives idle.
    pub(crate) fn on_nothing_to_send(&mut self) {
        self.next_send_time = None;
        self.credit = Duration::ZERO;
    }

    /// The armed pace schedule, always advertised through the sender's
    /// `next_deadline` — the module contract (mod.rs) guarantees a drain
    /// at this instant, which performs the idle reset above.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.next_send_time
    }

    // ---- stats gauges ----

    pub(crate) fn period_us(&self) -> u64 {
        self.period.as_micros() as u64
    }

    pub(crate) fn max_bw(&self) -> u64 {
        self.max_bw
    }

    /// Last measured input rate (0 for fixed ceilings and before the
    /// first estimator window closes).
    pub(crate) fn input_rate(&self) -> u64 {
        match &self.mode {
            PacerMode::Estimated { est, .. } => est.measured(),
            PacerMode::Fixed => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn us(n: u64) -> Duration {
        Duration::from_micros(n)
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn avg_iir_matches_spec_filter() {
        // §1.4: avg_iir<N>(old, sample) = (old·(N-1) + sample) / N with
        // integer division; N = 128 is the AvgPayloadSize smoother (§3.3).
        // A converged filter stays put.
        assert_eq!(avg_iir::<128>(1316, 1316), 1316);
        assert_eq!(avg_iir::<128>(0, 0), 0);
        // One step, truncating.
        assert_eq!(avg_iir::<128>(1316, 188), (1316 * 127 + 188) / 128);
        assert_eq!(avg_iir::<128>(1316, 188), 1307);
        // Small samples truncate away entirely until they accumulate.
        assert_eq!(avg_iir::<128>(0, 127), 0);
        assert_eq!(avg_iir::<128>(0, 128), 1);
    }

    // ---- input-rate estimator (transmission.md §3.3, buffer.cpp:299-333) ----

    #[test]
    fn estimator_first_sample_stamps_window_only() {
        // buffer.cpp:305-309: the first sample after construction stamps
        // m_tsInRateStartTime and returns — its bytes are never counted.
        let t0 = Instant::now();
        let mut est = InputRateEstimator::new();
        est.on_input(t0, 1000);
        // The second sample closes the fast-start window: only ITS bytes
        // count — (500 + 1·44)·1e6 / 600_000 µs = 906.67 → 906.
        est.on_input(t0 + ms(600), 500);
        assert_eq!(est.measured(), 906);
    }

    #[test]
    fn estimator_closes_strictly_after_period() {
        // buffer.cpp:318: close requires elapsed strictly greater than
        // the window period — at exactly 500 ms the window stays open.
        let t0 = Instant::now();
        let mut est = InputRateEstimator::new();
        est.on_input(t0, 100); // stamps only
        est.on_input(t0 + ms(500), 100); // elapsed == period: no close
        assert_eq!(est.measured(), 0);
        // One µs past: closes with both counted samples —
        // (200 + 2·44)·1e6 / 500_001 = 575.99 → 575.
        est.on_input(t0 + ms(500) + us(1), 100);
        assert_eq!(est.measured(), 575);
    }

    #[test]
    fn estimator_close_comparison_truncates_elapsed_to_whole_microseconds() {
        // buffer.cpp:317-318: libsrt compares count_microseconds(elapsed)
        // — an integer-truncated value — against the period, so a sample
        // landing inside (period, period + 1 µs) keeps the window open and
        // its bytes count toward the CURRENT window, not the next one.
        let t0 = Instant::now();
        let mut est = InputRateEstimator::new();
        est.on_input(t0, 100); // stamps only
        // True elapsed 500 000.4 µs truncates to 500 000: not > 500 000.
        est.on_input(t0 + ms(500) + Duration::from_nanos(400), 100);
        assert_eq!(est.measured(), 0, "sub-µs overshoot must not close the window");
        // The next whole-µs sample closes with BOTH counted samples —
        // (200 + 2·44)·1e6 / 500_001 = 575.99 → 575.
        est.on_input(t0 + ms(500) + us(1), 100);
        assert_eq!(est.measured(), 575);
    }

    #[test]
    fn estimator_fast_start_early_close_above_2000_pkts() {
        // buffer.cpp:315: in the fast-start window, crossing
        // INPUTRATE_MAX_PACKETS (strict >) closes the window early.
        let t0 = Instant::now();
        let mut est = InputRateEstimator::new();
        est.on_input(t0, 100); // stamps only
        for _ in 0 .. 2000 {
            est.on_input(t0 + us(10), 100);
        }
        // Exactly 2000 counted packets: strict >, still open.
        assert_eq!(est.measured(), 0);
        // 2001st closes: 2001·(100 + 44) bytes over 20 µs.
        est.on_input(t0 + us(20), 100);
        assert_eq!(est.measured(), 2001 * 144 * 1_000_000 / 20);
    }

    #[test]
    fn estimator_adds_44_per_packet_and_truncates() {
        // buffer.cpp:321-322: SRT_DATA_HDR_SIZE is charged per packet
        // once, at close; the division truncates.
        let t0 = Instant::now();
        let mut est = InputRateEstimator::new();
        est.on_input(t0, 999); // stamps only
        est.on_input(t0 + ms(100), 100);
        est.on_input(t0 + ms(200), 100);
        est.on_input(t0 + ms(700), 100);
        // (300 + 3·44)·1e6 / 700_000 = 617.14 → 617.
        assert_eq!(est.measured(), (300 + 3 * 44) * 1_000_000 / 700_000);
        assert_eq!(est.measured(), 617);
    }

    #[test]
    fn estimator_period_becomes_one_second_after_first_close() {
        // buffer.cpp:330: any close switches the window length to
        // INPUTRATE_RUNNING — a 600 ms gap that would have closed the
        // fast-start window no longer does.
        let t0 = Instant::now();
        let mut est = InputRateEstimator::new();
        est.on_input(t0, 500); // stamps only
        est.on_input(t0 + ms(501), 500); // first close (fast-start)
        // (500 + 44)·1e6 / 501_000 = 1085.8 → 1085.
        assert_eq!(est.measured(), 1085);
        est.on_input(t0 + ms(501) + ms(600), 500);
        assert_eq!(est.measured(), 1085, "600 ms must not close a 1 s window");
        // Strictly past 1 s: closes with both counted samples —
        // (1000 + 2·44)·1e6 / 1_001_000 = 1086.9 → 1086.
        est.on_input(t0 + ms(501) + ms(1001), 500);
        assert_eq!(est.measured(), 1086);
    }

    #[test]
    fn estimator_same_instant_burst_never_divides_by_zero() {
        // The establish-time pending_send flush pushes up to 8192 packets
        // with one identical `now` (core/mod.rs), tripping the >2000
        // early close at elapsed == 0 — libsrt would divide by zero. The
        // guard must suppress the close and keep the counters.
        let t0 = Instant::now();
        let mut est = InputRateEstimator::new();
        for _ in 0 .. 8192 {
            est.on_input(t0, 1316);
        }
        assert_eq!(est.measured(), 0, "no window may close with elapsed 0");
        // The next distinct-instant push closes normally with everything
        // accumulated: 8192·(1316 + 44) bytes over 100 µs.
        est.on_input(t0 + us(100), 1316);
        assert_eq!(est.measured(), 8192 * (1316 + 44) * 1_000_000 / 100);
    }

    #[test]
    fn estimator_stale_rate_persists_over_silence() {
        // The rate is only ever recomputed inside on_input: silence never
        // touches it and there is no decay path — a stale value persists
        // forever (libsrt behavior; the Estimated mode's
        // `min_bytes_per_sec` floor is the operator's remedy).
        let t0 = Instant::now();
        let mut est = InputRateEstimator::new();
        est.on_input(t0, 500);
        est.on_input(t0 + ms(501), 500);
        let rate = est.measured();
        assert_ne!(rate, 0);
        assert_eq!(est.ceiling_input(), rate);
        assert_eq!(est.measured(), rate);
    }

    #[test]
    fn estimator_measured_is_zero_before_first_close() {
        // Two readers, two inits (buffer.h:207): the ceiling math gets
        // BW_INFINITE (the unpaced fast-start grace), stats get 0 — never
        // report the fictitious 125 MB/s to operators.
        let est = InputRateEstimator::new();
        assert_eq!(est.measured(), 0);
        assert_eq!(est.ceiling_input(), BW_INFINITE);
    }

    // ---- ceiling and period math (transmission.md §3.3) ----

    #[test]
    fn with_overhead_truncates_like_libsrt() {
        // core.h:656-659: base·(100+pct)/100, integer truncation. The
        // boundary percentages are the SRTO_OHEADBW setter range.
        assert_eq!(with_overhead(1000, 5), 1050);
        assert_eq!(with_overhead(1000, 100), 2000);
        // (999·125)/100 = 1248.75 → 1248, never rounded up.
        assert_eq!(with_overhead(999, 25), 1248);
        assert_eq!(with_overhead(1, 5), 1);
        // Saturating hardening: absurd bases must not overflow.
        assert_eq!(with_overhead(u64::MAX, 100), u64::MAX / 100);
    }

    #[test]
    fn period_is_whole_microseconds() {
        // congctl.cpp:173-180 + core.cpp:7371-7379: the period is f64
        // math truncated to whole µs. BW_INFINITE with the 1316 init avg:
        // 1e6·(1316+44)/125e6 = 10.88 → exactly 10 µs.
        let p = Pacer::new(&Bandwidth::Max { bytes_per_sec: BW_INFINITE }, 1456).unwrap();
        assert_eq!(p.period_us(), 10);
        // The IIR init is min(1316, max_payload): a 1000-byte cap gives
        // 1e6·(1000+44)/125e6 = 8.35 → 8 µs.
        let p = Pacer::new(&Bandwidth::Max { bytes_per_sec: BW_INFINITE }, 1000).unwrap();
        assert_eq!(p.period_us(), 8);
    }

    #[test]
    fn unlimited_mode_constructs_no_pacer() {
        // Divergence pin: `Unlimited` disables pacing structurally rather
        // than gating at libsrt's ~10.9 µs BW_INFINITE default — default
        // behavior must stay exactly as before pacing existed.
        assert!(Pacer::new(&Bandwidth::Unlimited, 1456).is_none());
    }

    #[test]
    fn input_mode_ceiling_computed_once_with_overhead() {
        // Input mode: ceiling = withOverhead(declared rate), fixed at
        // construction (options are immutable post-connect); the
        // estimator is off, refresh never re-derives the ceiling.
        let bw = Bandwidth::Input { bytes_per_sec: 1_000_000, overhead_pct: 25 };
        let mut p = Pacer::new(&bw, 1456).unwrap();
        assert_eq!(p.max_bw(), 1_250_000);
        let t0 = Instant::now();
        p.on_input(t0, 1316);
        p.on_input(t0 + Duration::from_secs(10), 1316);
        p.refresh();
        assert_eq!(p.max_bw(), 1_250_000);
        assert_eq!(p.input_rate(), 0);
        // period = trunc(1e6·(1316+44)/1_250_000) = 1088 µs, exact.
        assert_eq!(p.period_us(), 1088);
    }

    #[test]
    fn estimated_refresh_keeps_ceiling_on_zero_bw() {
        // LiveCC updateBandwidth's `if (bw == 0) return;`
        // (congctl.cpp:209-212): a degenerate window (measured 0) with
        // min == 0 keeps the previous ceiling instead of zeroing it.
        let bw = Bandwidth::Estimated { min_bytes_per_sec: 0, overhead_pct: 25 };
        let mut p = Pacer::new(&bw, 1456).unwrap();
        let t0 = Instant::now();
        // One 0-byte payload over 100 s: (0 + 44)·1e6/1e8 = 0.44 → rate 0.
        p.on_input(t0, 0);
        p.on_input(t0 + Duration::from_secs(100), 0);
        p.refresh();
        assert_eq!(p.max_bw(), BW_INFINITE, "zero estimate must keep the ceiling");
    }

    #[test]
    fn estimated_min_floor_applies_only_against_estimate() {
        // core.cpp:7344-7363: auto-mode ceiling =
        // withOverhead(max(MININPUTBW, estimate)) — the floor engages
        // only while the measured rate sits below it.
        let bw = Bandwidth::Estimated { min_bytes_per_sec: 100_000, overhead_pct: 25 };
        let mut p = Pacer::new(&bw, 1456).unwrap();
        let t0 = Instant::now();
        // First window measures ~1085 B/s, far below min: the floor wins.
        p.on_input(t0, 500); // stamps only
        p.on_input(t0 + ms(501), 500);
        assert_eq!(p.input_rate(), 1085);
        p.refresh();
        assert_eq!(p.max_bw(), with_overhead(100_000, 25));
        // Second window measures above the floor: the estimate wins —
        // 200 pkts of 1316 over 1.001 s = 200·1360·1e6/1_001_000 = 271_728.
        for i in 1 ..= 199u64 {
            p.on_input(t0 + ms(501) + ms(5 * i), 1316);
        }
        p.on_input(t0 + ms(501) + ms(1001), 1316);
        assert_eq!(p.input_rate(), 271_728);
        p.refresh();
        assert_eq!(p.max_bw(), with_overhead(271_728, 25));
    }
}
