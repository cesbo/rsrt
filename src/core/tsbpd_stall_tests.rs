//! Regression tests for TSBPD across long data stalls (no tokio, no UDP:
//! a synthetic clock drives the sans-I/O `Receiver` directly).
//!
//! Only DATA packets feed `core::time::TimestampExtender` — keepalives and
//! other control packets never reach it — so a stalled source (encoder
//! paused, input dry) held up by keepalives produces a >2^31 µs gap between
//! observed timestamps. The extender used to follow the shortest signed
//! 32-bit path from the previous timestamp, which mapped the resumed stream
//! ~26.5 minutes into the past: every deadline landed pre-`now`, packets
//! delivered instantly with zero TSBPD buffering, and holes were skipped at
//! the next `poll_deliver` before any NAK-recovered retransmission could
//! arrive — permanently disabling ARQ. These tests pin the fixed,
//! arrival-time-guided behavior.

use std::time::{
    Duration,
    Instant,
};

use crate::{
    core::{
        Receiver,
        ReceiverConfig,
    },
    packet::{
        ControlType,
        DataPacket,
        EncryptionFlags,
        MsgNumber,
        PacketPosition,
        SeqNumber,
        SocketId,
        Timestamp,
    },
};

const ISN: u32 = 1000;
const LATENCY: Duration = Duration::from_millis(120);
/// 45 minutes: larger than 2^31 µs (~35.8 min), smaller than one 2^32 µs
/// wire-clock wrap, so the wire timestamp itself does not wrap.
const STALL_US: u64 = 45 * 60 * 1_000_000;

fn rx(t0: Instant) -> Receiver {
    Receiver::new(
        t0,
        ReceiverConfig {
            initial_seq: SeqNumber::new(ISN),
            rcv_latency: LATENCY,
            buffer_pkts: 8192,
        },
    )
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

fn us(n: u64) -> Duration {
    Duration::from_micros(n)
}

/// After a 45-min stall the next packet is held for the full receiver
/// latency, not delivered instantly off a corrupted (past) deadline.
#[test]
fn post_stall_packet_held_full_latency() {
    let t0 = Instant::now();
    let mut r = rx(t0);

    r.handle_data(t0, data(ISN, 0));
    assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));

    // Source stalls for 45 min (keepalives, which never reach the receiver's
    // extender, hold the connection up), then resumes.
    let resume = t0 + us(STALL_US);
    r.handle_data(resume, data(ISN + 1, STALL_US as u32));

    // Broken extension put the deadline ~26.5 min in the past: delivery
    // would happen immediately. The packet must be buffered for LATENCY.
    assert_eq!(r.poll_deliver(resume), None);
    assert_eq!(r.poll_deliver(resume + LATENCY - us(1)), None);
    assert_eq!(
        r.poll_deliver(resume + LATENCY),
        Some(vec![(ISN + 1) as u8])
    );
    assert_eq!(r.stats().pkts_dropped, 0);
}

/// A hole in the first burst after a stall survives until its real TSBPD
/// deadline, leaving the NAK/retransmission cycle time to repair it.
#[test]
fn post_stall_hole_survives_until_real_deadline() {
    let t0 = Instant::now();
    let mut r = rx(t0);

    r.handle_data(t0, data(ISN, 0));
    assert_eq!(r.poll_deliver(t0 + LATENCY), Some(vec![ISN as u8]));

    // Post-stall burst arrives with its first packet (ISN+1) lost in
    // transit: ISN+2 creates the hole and triggers an immediate NAK.
    let resume = t0 + us(STALL_US);
    r.handle_data(resume, data(ISN + 2, STALL_US as u32 + 1_000));
    let nak = std::iter::from_fn(|| r.poll_control(resume)).find_map(|c| match c {
        ControlType::Nak(ranges) => Some(ranges),
        _ => None,
    });
    assert_eq!(
        nak.and_then(|rs| rs.first().map(|e| (e.first.value(), e.last.value()))),
        Some((ISN + 1, ISN + 1)),
    );

    // Broken extension skipped the hole on the very next poll_deliver and
    // released ISN+2 (dropping ISN+1 forever). The hole must hold delivery.
    assert_eq!(r.poll_deliver(resume), None);
    assert_eq!(r.stats().pkts_dropped, 0);

    // The NAK-recovered retransmission (original timestamp) arrives one
    // round-trip later — well inside the latency window — and both packets
    // release in order, each exactly at its own deadline.
    let mut rexmit = data(ISN + 1, STALL_US as u32);
    rexmit.retransmitted = true;
    r.handle_data(resume + Duration::from_millis(20), rexmit);

    assert_eq!(r.poll_deliver(resume + LATENCY - us(1)), None);
    assert_eq!(
        r.poll_deliver(resume + LATENCY),
        Some(vec![(ISN + 1) as u8])
    );
    assert_eq!(r.poll_deliver(resume + LATENCY + us(999)), None);
    assert_eq!(
        r.poll_deliver(resume + LATENCY + us(1_000)),
        Some(vec![(ISN + 2) as u8])
    );
    assert_eq!(r.stats().pkts_dropped, 0);
}
