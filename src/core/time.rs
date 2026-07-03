//! Time base: local `Instant` ↔ 32-bit wire timestamps (µs), and extension
//! of the peer's wrapping timestamps to a monotonic 64-bit scale.

use std::time::Instant;

use crate::packet::Timestamp;

/// Maps local `Instant`s to wire timestamps: microseconds since the socket
/// started, truncated to 32 bits (wraps every ~71.6 minutes — receivers must
/// use [`TimestampExtender`] on the peer's timestamps).
#[derive(Clone, Copy, Debug)]
pub struct Timebase {
    start: Instant,
}

impl Timebase {
    pub fn new(start: Instant) -> Self {
        Timebase { start }
    }

    pub fn start(&self) -> Instant {
        self.start
    }

    /// Wire timestamp for a local instant (which must not precede `start`).
    pub fn timestamp(&self, now: Instant) -> Timestamp {
        let us = now.saturating_duration_since(self.start).as_micros();
        Timestamp(us as u32)
    }
}

/// Extends a stream of wrapping 32-bit µs timestamps into a monotonic-ish
/// u64 scale, guided by local arrival time.
///
/// The first call anchors the peer's wire clock to the local clock. Every
/// later timestamp maps to the 2^32-period candidate nearest the locally
/// *expected* wire time (`anchor_ext + elapsed-since-anchor`), so forward
/// wraps and reordered slightly-old packets (including ones straddling a
/// wrap boundary) extend correctly regardless of how long the stream stays
/// silent between observed timestamps.
///
/// That gap is unbounded in practice: only DATA packets reach the extender
/// (keepalives and other control packets never do), and a live source can
/// stall arbitrarily long while keepalives hold the connection up — the
/// stall may even span one or more 2^32 µs wraps of the wire clock.
/// Correctness only requires the accumulated sender/receiver clock drift
/// plus one-way-delay variation to stay below ±2^31 µs (~35.8 minutes);
/// real clock drift is µs-per-minute scale, orders of magnitude inside
/// that tolerance even for connections running for months.
#[derive(Debug, Default)]
pub struct TimestampExtender {
    /// Local arrival instant and extended value of the first timestamp.
    anchor: Option<(Instant, u64)>,
}

impl TimestampExtender {
    pub fn new() -> Self {
        Self::default()
    }

    /// Extends `ts`, observed at local time `now`, onto the 64-bit scale.
    pub fn extend(&mut self, ts: Timestamp, now: Instant) -> u64 {
        let (anchor_instant, anchor_ext) = match self.anchor {
            Some(a) => a,
            None => {
                self.anchor = Some((now, ts.0 as u64));
                return ts.0 as u64;
            }
        };
        // Where the peer's wire clock should read now, per the local clock
        // (`saturating`: a `now` predating the anchor degrades to the plain
        // shortest path from the anchor instead of panicking).
        let elapsed = now.saturating_duration_since(anchor_instant).as_micros() as u64;
        let expected = anchor_ext + elapsed;
        // Signed shortest path from `expected` picks the 2^32-period
        // candidate of `ts` nearest to it, clamped at 0.
        let delta = ts.0.wrapping_sub(expected as u32) as i32;
        expected.saturating_add_signed(delta as i64)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn timebase_truncates_to_32_bits() {
        let start = Instant::now();
        let tb = Timebase::new(start);
        assert_eq!(tb.timestamp(start), Timestamp(0));
        let later = start + Duration::from_micros(1_000_000);
        assert_eq!(tb.timestamp(later), Timestamp(1_000_000));
        // Past the 32-bit wrap (~71.6 min).
        let wrapped = start + Duration::from_micros((1u64 << 32) + 5);
        assert_eq!(tb.timestamp(wrapped), Timestamp(5));
    }

    fn us(n: u64) -> Duration {
        Duration::from_micros(n)
    }

    #[test]
    fn extender_monotonic_without_wrap() {
        let t0 = Instant::now();
        let mut ex = TimestampExtender::new();
        assert_eq!(ex.extend(Timestamp(100), t0), 100);
        assert_eq!(ex.extend(Timestamp(200), t0 + us(100)), 200);
    }

    #[test]
    fn extender_handles_forward_wrap() {
        let t0 = Instant::now();
        let mut ex = TimestampExtender::new();
        assert_eq!(
            ex.extend(Timestamp(u32::MAX - 10), t0),
            (u32::MAX - 10) as u64
        );
        // Wrapped around: should land one period up, not jump backwards.
        assert_eq!(ex.extend(Timestamp(10), t0 + us(21)), (1u64 << 32) + 10);
    }

    #[test]
    fn extender_tolerates_backward_jitter() {
        let t0 = Instant::now();
        let mut ex = TimestampExtender::new();
        ex.extend(Timestamp(1_000_000), t0);
        // A reordered slightly-older packet stays in the same epoch.
        assert_eq!(ex.extend(Timestamp(999_000), t0 + us(100)), 999_000);
        assert_eq!(ex.extend(Timestamp(1_001_000), t0 + us(1_050)), 1_001_000);
    }

    #[test]
    fn extender_jitter_across_wrap_boundary() {
        let t0 = Instant::now();
        let mut ex = TimestampExtender::new();
        // Stream that has already wrapped once.
        ex.extend(Timestamp(u32::MAX - 10), t0);
        assert_eq!(ex.extend(Timestamp(30), t0 + us(41)), (1u64 << 32) + 30);
        // A late pre-wrap packet maps back below the wrap, not a period up.
        assert_eq!(
            ex.extend(Timestamp(u32::MAX - 5), t0 + us(50)),
            (u32::MAX - 5) as u64
        );
        // And the stream continues past the wrap correctly.
        assert_eq!(ex.extend(Timestamp(50), t0 + us(61)), (1u64 << 32) + 50);
    }

    #[test]
    fn extender_tolerates_delay_variation() {
        // Arrival time only *guides* the extension: a packet delayed 200 ms
        // relative to the anchor's one-way delay still maps to its own
        // timestamp, not to the arrival-derived expectation.
        let t0 = Instant::now();
        let mut ex = TimestampExtender::new();
        ex.extend(Timestamp(0), t0);
        assert_eq!(
            ex.extend(Timestamp(60_000_000), t0 + us(60_200_000)),
            60_000_000
        );
        // And one that arrives 200 ms *early* relative to the anchor delay.
        assert_eq!(
            ex.extend(Timestamp(61_000_000), t0 + us(60_800_000)),
            61_000_000
        );
    }

    /// Regression: only DATA packets feed the extender, so a stalled source
    /// (keepalives holding the connection up) creates timestamp gaps larger
    /// than 2^31 µs. The old shortest-path-from-last logic mapped a 45-min
    /// gap ~26.5 min BACKWARD (saturating at 0), permanently breaking TSBPD.
    #[test]
    fn extender_survives_45_min_data_gap() {
        let t0 = Instant::now();
        let mut ex = TimestampExtender::new();
        assert_eq!(ex.extend(Timestamp(1_000_000), t0), 1_000_000);

        let gap: u64 = 45 * 60 * 1_000_000; // 2.7e9 µs > 2^31, < 2^32: no wire wrap
        let ts = Timestamp(1_000_000u32 + gap as u32);
        assert_eq!(ex.extend(ts, t0 + us(gap)), 1_000_000 + gap);
        // The stream then continues normally from the new position.
        assert_eq!(
            ex.extend(Timestamp(ts.0 + 20_000), t0 + us(gap + 20_000)),
            1_000_000 + gap + 20_000,
        );
    }

    /// Regression: a stall may span one or more 2^32 µs wire-clock wraps
    /// with no packet observed anywhere near the wrap boundary. libsrt's
    /// 30 s wrap-period rule breaks here; arrival-guided extension does not.
    #[test]
    fn extender_survives_data_gap_across_wrap_boundary() {
        let t0 = Instant::now();
        let mut ex = TimestampExtender::new();
        assert_eq!(ex.extend(Timestamp(5_000_000), t0), 5_000_000);

        // 100 min: one full wrap passes with no data at all.
        let gap: u64 = 100 * 60 * 1_000_000;
        let ext = 5_000_000 + gap;
        assert_eq!(ex.extend(Timestamp(ext as u32), t0 + us(gap)), ext);

        // Second stall of 3 h (spans two more wraps), and the local clock
        // has drifted 100 ms relative to the peer by the time it ends.
        let gap2: u64 = 3 * 60 * 60 * 1_000_000;
        let ext2 = ext + gap2;
        assert_eq!(
            ex.extend(Timestamp(ext2 as u32), t0 + us(gap + gap2 + 100_000)),
            ext2,
        );
    }
}
