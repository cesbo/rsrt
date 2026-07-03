//! Control packets: wire layout per docs/spec/packets.md.

use tracing::{
    trace,
    warn,
};

use super::{
    handshake::HandshakeCif,
    put_u32,
    read_u32,
    types::{
        MsgNumber,
        SeqNumber,
        SocketId,
        Timestamp,
    },
    PacketError,
    HEADER_SIZE,
};

/// SRT control packet (F bit = 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPacket {
    pub timestamp: Timestamp,
    pub dst_socket_id: SocketId,
    pub control_type: ControlType,
}

/// Control packet type together with its Control Information Field (CIF).
///
/// Type codes (docs/spec/packets.md): HANDSHAKE 0x0000, KEEPALIVE 0x0001,
/// ACK 0x0002, NAK 0x0003, CONGESTION-WARNING 0x0004, SHUTDOWN 0x0005,
/// ACKACK 0x0006, DROPREQ 0x0007, PEERERROR 0x0008.
///
/// USER-DEFINED (0x7FFF) and unknown types surface as
/// `PacketError::UnknownControlType` and are dropped (and logged) by the
/// connection layer — they never break a live-mode connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlType {
    Handshake(HandshakeCif),
    KeepAlive,
    Ack {
        /// ACK sequence number (type-specific info field), echoed by ACKACK.
        /// 0 for light ACKs.
        ack_number: u32,
        cif: AckCif,
    },
    Nak(Vec<LossRange>),
    /// Deprecated in SRT; parsed for tolerance, ignored by the connection.
    CongestionWarning,
    Shutdown,
    AckAck {
        ack_number: u32,
    },
    DropRequest {
        /// Message number of the dropped message (type-specific info field).
        msg_number: MsgNumber,
        first: SeqNumber,
        last: SeqNumber,
    },
    PeerError {
        code: u32,
    },
}

/// ACK Control Information Field.
///
/// Wire variants by CIF length (docs/spec/packets.md):
/// - Light ACK: `last_ack_seq` only (4 bytes) — all other fields `None`.
/// - Small ACK: + `rtt_us`, `rtt_var_us`, `avail_buf_pkts` (16 bytes).
/// - Full ACK: + `recv_rate_pkts`, `link_capacity_pkts` and optionally `recv_rate_bytes` (24 or 28
///   bytes).
///
/// The encoder writes the longest contiguous prefix of `Some` fields (in
/// declaration order); the parser fills fields according to the CIF length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AckCif {
    /// Sequence number of the last contiguously received packet, plus 1.
    pub last_ack_seq: SeqNumber,
    pub rtt_us: Option<u32>,
    pub rtt_var_us: Option<u32>,
    pub avail_buf_pkts: Option<u32>,
    pub recv_rate_pkts: Option<u32>,
    pub link_capacity_pkts: Option<u32>,
    pub recv_rate_bytes: Option<u32>,
}

/// Inclusive range of lost sequence numbers (`first == last` for a single
/// loss). NAK wire encoding: single numbers as-is; ranges as two 32-bit
/// words with the MSB set on the first (docs/spec/packets.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossRange {
    pub first: SeqNumber,
    pub last: SeqNumber,
}

/// MSB flag on the `lo` word of a NAK range pair.
const NAK_RANGE_FLAG: u32 = 0x8000_0000;

impl ControlType {
    /// 15-bit wire control type code.
    fn type_code(&self) -> u32 {
        match self {
            ControlType::Handshake(_) => 0x0000,
            ControlType::KeepAlive => 0x0001,
            ControlType::Ack { .. } => 0x0002,
            ControlType::Nak(_) => 0x0003,
            ControlType::CongestionWarning => 0x0004,
            ControlType::Shutdown => 0x0005,
            ControlType::AckAck { .. } => 0x0006,
            ControlType::DropRequest { .. } => 0x0007,
            ControlType::PeerError { .. } => 0x0008,
        }
    }

    /// Type-specific Information (header word 1).
    fn type_specific_info(&self) -> u32 {
        match self {
            ControlType::Ack { ack_number, .. } => *ack_number,
            ControlType::AckAck { ack_number } => *ack_number,
            ControlType::DropRequest { msg_number, .. } => msg_number.value(),
            ControlType::PeerError { code } => *code,
            _ => 0,
        }
    }
}

impl ControlPacket {
    /// Parses a complete control packet. The caller has already checked
    /// that the F bit (MSB of the first byte) is 1.
    pub fn parse(buf: &[u8]) -> Result<ControlPacket, PacketError> {
        if buf.len() < HEADER_SIZE {
            return Err(PacketError::TooShort);
        }
        let word0 = read_u32(buf, 0);
        let type_code = ((word0 >> 16) & 0x7FFF) as u16;
        // Subtype: meaningful only for user-defined (0x7FFF); ignored on
        // standard types (libsrt does not validate it).
        let subtype = (word0 & 0xFFFF) as u16;
        let info = read_u32(buf, 4);
        let cif = &buf[HEADER_SIZE ..];

        let control_type = match type_code {
            0x0000 => ControlType::Handshake(HandshakeCif::parse_cif(cif)?),
            // Nominally CIF-less types: libsrt sends a 4-byte zero pad;
            // accept any CIF length and ignore the bytes.
            0x0001 => ControlType::KeepAlive,
            0x0002 => ControlType::Ack {
                ack_number: info,
                cif: parse_ack_cif(cif)?,
            },
            0x0003 => ControlType::Nak(parse_loss_list(cif)?),
            0x0004 => ControlType::CongestionWarning,
            0x0005 => ControlType::Shutdown,
            0x0006 => ControlType::AckAck { ack_number: info },
            0x0007 => {
                if cif.len() < 8 {
                    return Err(PacketError::BadCif("DROPREQ CIF shorter than 2 words"));
                }
                ControlType::DropRequest {
                    // Upper bits of the info word may carry garbage flags:
                    // MsgNumber::new masks to the 26-bit field.
                    msg_number: MsgNumber::new(info),
                    first: SeqNumber::new(read_u32(cif, 0)),
                    last: SeqNumber::new(read_u32(cif, 4)),
                }
            }
            0x0008 => ControlType::PeerError { code: info },
            // User-defined/extended (UMSG_EXT): the subtype is the extended
            // type; none are implemented (HSv5-only, unencrypted).
            0x7FFF => return Err(PacketError::UnknownControlType(subtype)),
            other => return Err(PacketError::UnknownControlType(other)),
        };
        trace!(type_code, cif_len = cif.len(), "control packet parsed");
        Ok(ControlPacket {
            timestamp: Timestamp(read_u32(buf, 8)),
            dst_socket_id: SocketId(read_u32(buf, 12)),
            control_type,
        })
    }

    /// Appends the encoded packet (header + CIF) to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, 0x8000_0000 | (self.control_type.type_code() << 16));
        put_u32(out, self.control_type.type_specific_info());
        put_u32(out, self.timestamp.0);
        put_u32(out, self.dst_socket_id.0);
        match &self.control_type {
            ControlType::Handshake(cif) => cif.encode_cif(out),
            ControlType::Ack { cif, .. } => encode_ack_cif(cif, out),
            ControlType::Nak(list) => encode_loss_list(list, out),
            ControlType::DropRequest { first, last, .. } => {
                put_u32(out, first.value());
                put_u32(out, last.value());
            }
            // Nominally CIF-less packets carry libsrt's 4-byte zero pad
            // (m_extra_pad) → 20-byte packets, matching the wire exactly.
            ControlType::KeepAlive
            | ControlType::CongestionWarning
            | ControlType::Shutdown
            | ControlType::AckAck { .. }
            | ControlType::PeerError { .. } => put_u32(out, 0),
        }
    }
}

/// Parses the ACK CIF; the variant is determined purely by length
/// (4 = Light, 16 = Small, 24/28 = Full; ≥ 32 = ignore the extra words).
fn parse_ack_cif(cif: &[u8]) -> Result<AckCif, PacketError> {
    if cif.len() == 4 {
        // Light ACK.
        return Ok(AckCif {
            last_ack_seq: SeqNumber::new(read_u32(cif, 0)),
            ..AckCif::default()
        });
    }
    if cif.len() < 16 {
        return Err(PacketError::BadCif("ACK CIF shorter than 4 words"));
    }
    if !cif.len().is_multiple_of(4) {
        warn!(
            len = cif.len(),
            "ACK CIF length not a multiple of 4; ignoring trailing bytes"
        );
    }
    let words = cif.len() / 4;
    let mut ack = AckCif {
        last_ack_seq: SeqNumber::new(read_u32(cif, 0)),
        rtt_us: Some(read_u32(cif, 4)),
        rtt_var_us: Some(read_u32(cif, 8)),
        avail_buf_pkts: Some(read_u32(cif, 12)),
        ..AckCif::default()
    };
    // Rate/capacity words come as a pair; a 5-word CIF is out-of-spec, so
    // only take the pair when both words are present.
    if words >= 6 {
        ack.recv_rate_pkts = Some(read_u32(cif, 16));
        ack.link_capacity_pkts = Some(read_u32(cif, 20));
    }
    if words >= 7 {
        ack.recv_rate_bytes = Some(read_u32(cif, 24));
    }
    // Words beyond 7 (the VER102-only 8-word variant) are ignored.
    Ok(ack)
}

/// Encodes the longest contiguous prefix of `Some` fields; a Light ACK
/// (`last_ack_seq` alone) is exactly 4 bytes — never padded.
fn encode_ack_cif(cif: &AckCif, out: &mut Vec<u8>) {
    put_u32(out, cif.last_ack_seq.value());
    for field in [
        cif.rtt_us,
        cif.rtt_var_us,
        cif.avail_buf_pkts,
        cif.recv_rate_pkts,
        cif.link_capacity_pkts,
        cif.recv_rate_bytes,
    ] {
        match field {
            Some(value) => put_u32(out, value),
            None => break,
        }
    }
}

fn parse_loss_list(cif: &[u8]) -> Result<Vec<LossRange>, PacketError> {
    let words = cif.len() / 4;
    if words == 0 {
        return Err(PacketError::BadCif("empty NAK loss list"));
    }
    if !cif.len().is_multiple_of(4) {
        warn!(
            len = cif.len(),
            "NAK CIF length not a multiple of 4; ignoring trailing bytes"
        );
    }
    let mut list = Vec::new();
    let mut i = 0;
    while i < words {
        let word = read_u32(cif, i * 4);
        if word & NAK_RANGE_FLAG != 0 {
            if i + 1 >= words {
                return Err(PacketError::BadCif("NAK range missing end word"));
            }
            let first = SeqNumber::new(word);
            let last = SeqNumber::new(read_u32(cif, (i + 1) * 4));
            // Circular compare, like libsrt's sender-side validation.
            if first.diff(last) > 0 {
                return Err(PacketError::BadCif("NAK range start after end"));
            }
            list.push(LossRange { first, last });
            i += 2;
        } else {
            let seq = SeqNumber::new(word);
            list.push(LossRange {
                first: seq,
                last: seq,
            });
            i += 1;
        }
    }
    Ok(list)
}

fn encode_loss_list(list: &[LossRange], out: &mut Vec<u8>) {
    for range in list {
        if range.first == range.last {
            // MSB is clear automatically: sequence numbers are 31-bit.
            put_u32(out, range.first.value());
        } else {
            debug_assert!(
                range.first.diff(range.last) < 0,
                "NAK range start after end"
            );
            put_u32(out, range.first.value() | NAK_RANGE_FLAG);
            put_u32(out, range.last.value());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: Timestamp = Timestamp(0x0001_E240); // 123456 µs
    const DST: SocketId = SocketId(0x0000_0042);

    fn pkt(control_type: ControlType) -> ControlPacket {
        ControlPacket {
            timestamp: TS,
            dst_socket_id: DST,
            control_type,
        }
    }

    fn encode(p: &ControlPacket) -> Vec<u8> {
        let mut out = Vec::new();
        p.encode(&mut out);
        out
    }

    /// Header bytes shared by the vectors below: word 0 built from the type,
    /// then Type-specific Information, timestamp, destination socket id.
    fn header(type_code: u16, info: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(0x8000_0000u32 | ((type_code as u32) << 16)).to_be_bytes());
        v.extend_from_slice(&info.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0xE2, 0x40]); // TS
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x42]); // DST
        v
    }

    fn round_trip(p: &ControlPacket) {
        assert_eq!(&ControlPacket::parse(&encode(p)).unwrap(), p);
    }

    // ---- CIF-less types: exact bytes, pad on send, pad/no-pad on receive ----

    #[test]
    fn keepalive_exact_bytes_with_pad() {
        let bytes = encode(&pkt(ControlType::KeepAlive));
        let mut expect = header(0x0001, 0);
        expect.extend_from_slice(&[0, 0, 0, 0]); // 4-byte zero pad
        assert_eq!(bytes, expect);
        assert_eq!(bytes.len(), 20);
    }

    #[test]
    fn cifless_types_accept_pad_and_no_pad() {
        for (code, ct) in [
            (0x0001u16, ControlType::KeepAlive),
            (0x0004, ControlType::CongestionWarning),
            (0x0005, ControlType::Shutdown),
            (0x0006, ControlType::AckAck { ack_number: 7 }),
            (0x0008, ControlType::PeerError { code: 4000 }),
        ] {
            let info = ct.type_specific_info();
            // 16-byte form (no pad).
            let bare = header(code, info);
            assert_eq!(ControlPacket::parse(&bare).unwrap(), pkt(ct.clone()));
            // 20-byte form (zero pad).
            let mut padded = bare.clone();
            padded.extend_from_slice(&[0, 0, 0, 0]);
            assert_eq!(ControlPacket::parse(&padded).unwrap(), pkt(ct.clone()));
            // Non-zero / oversized CIF bytes are ignored too.
            let mut garbage = bare.clone();
            garbage.extend_from_slice(&[0xFF; 8]);
            assert_eq!(ControlPacket::parse(&garbage).unwrap(), pkt(ct.clone()));
            // Encoded form is always the 20-byte padded one.
            assert_eq!(encode(&pkt(ct.clone())).len(), 20);
        }
    }

    #[test]
    fn shutdown_exact_bytes() {
        let mut expect = header(0x0005, 0);
        expect.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(encode(&pkt(ControlType::Shutdown)), expect);
    }

    #[test]
    fn ackack_exact_bytes() {
        let p = pkt(ControlType::AckAck {
            ack_number: 0x0000_0102,
        });
        let mut expect = header(0x0006, 0x0000_0102);
        expect.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(encode(&p), expect);
        round_trip(&p);
    }

    #[test]
    fn peererror_exact_bytes() {
        let p = pkt(ControlType::PeerError { code: 4000 });
        let mut expect = header(0x0008, 4000);
        expect.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(encode(&p), expect);
        round_trip(&p);
    }

    #[test]
    fn subtype_ignored_on_standard_types() {
        let mut bytes = header(0x0001, 0);
        bytes[2] = 0x00;
        bytes[3] = 0xFF; // subtype = 0x00FF
        assert_eq!(
            ControlPacket::parse(&bytes).unwrap(),
            pkt(ControlType::KeepAlive)
        );
    }

    // ---- ACK ----

    fn full_ack_cif() -> AckCif {
        AckCif {
            last_ack_seq: SeqNumber::new(0x0000_1000),
            rtt_us: Some(100_000),
            rtt_var_us: Some(50_000),
            avail_buf_pkts: Some(8192),
            recv_rate_pkts: Some(1500),
            link_capacity_pkts: Some(20_000),
            recv_rate_bytes: Some(1_974_000),
        }
    }

    #[test]
    fn light_ack_exact_bytes_no_pad() {
        // Light ACK: ack_number 0, CIF exactly 4 bytes — the pad rule must
        // NOT apply (a padded light ACK would read as garbage).
        let p = pkt(ControlType::Ack {
            ack_number: 0,
            cif: AckCif {
                last_ack_seq: SeqNumber::new(0x0000_1000),
                ..AckCif::default()
            },
        });
        let bytes = encode(&p);
        let mut expect = header(0x0002, 0);
        expect.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]);
        assert_eq!(bytes, expect);
        assert_eq!(bytes.len(), 20);
        round_trip(&p);
    }

    #[test]
    fn full_ack_28_exact_bytes() {
        let p = pkt(ControlType::Ack {
            ack_number: 1,
            cif: full_ack_cif(),
        });
        let mut expect = header(0x0002, 1);
        expect.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // last ack seq
        expect.extend_from_slice(&[0x00, 0x01, 0x86, 0xA0]); // RTT 100000
        expect.extend_from_slice(&[0x00, 0x00, 0xC3, 0x50]); // RTTVar 50000
        expect.extend_from_slice(&[0x00, 0x00, 0x20, 0x00]); // buf 8192
        expect.extend_from_slice(&[0x00, 0x00, 0x05, 0xDC]); // 1500 pkts/s
        expect.extend_from_slice(&[0x00, 0x00, 0x4E, 0x20]); // 20000 pkts/s
        expect.extend_from_slice(&[0x00, 0x1E, 0x1E, 0xF0]); // 1974000 B/s
        assert_eq!(encode(&p), expect);
        assert_eq!(encode(&p).len(), 16 + 28);
        round_trip(&p);
    }

    #[test]
    fn ack_variants_distinguished_by_length() {
        // Small ACK (16-byte CIF) carries a real ACK number.
        let small = AckCif {
            recv_rate_pkts: None,
            link_capacity_pkts: None,
            recv_rate_bytes: None,
            ..full_ack_cif()
        };
        let p = pkt(ControlType::Ack {
            ack_number: 3,
            cif: small,
        });
        assert_eq!(encode(&p).len(), 16 + 16);
        round_trip(&p);

        // 24-byte Full ACK (UDT base, no bytes/sec word).
        let full24 = AckCif {
            recv_rate_bytes: None,
            ..full_ack_cif()
        };
        let p = pkt(ControlType::Ack {
            ack_number: 4,
            cif: full24,
        });
        assert_eq!(encode(&p).len(), 16 + 24);
        round_trip(&p);
    }

    #[test]
    fn ack_32_byte_cif_ignores_extra_word() {
        // VER102-only 8-word variant: word 7 must be ignored.
        let p = pkt(ControlType::Ack {
            ack_number: 1,
            cif: full_ack_cif(),
        });
        let mut bytes = encode(&p);
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(ControlPacket::parse(&bytes).unwrap(), p);
    }

    #[test]
    fn ack_trailing_partial_word_ignored() {
        let small = AckCif {
            recv_rate_pkts: None,
            link_capacity_pkts: None,
            recv_rate_bytes: None,
            ..full_ack_cif()
        };
        let p = pkt(ControlType::Ack {
            ack_number: 3,
            cif: small,
        });
        let mut bytes = encode(&p);
        bytes.extend_from_slice(&[0x01, 0x02]); // 18-byte CIF
        assert_eq!(ControlPacket::parse(&bytes).unwrap(), p);
    }

    #[test]
    fn ack_bad_cif_lengths_rejected() {
        for cif_len in [0usize, 3, 8, 12, 15] {
            let mut bytes = header(0x0002, 1);
            bytes.extend_from_slice(&vec![0u8; cif_len]);
            assert!(
                matches!(ControlPacket::parse(&bytes), Err(PacketError::BadCif(_))),
                "CIF len {cif_len} must be rejected"
            );
        }
    }

    // ---- NAK ----

    #[test]
    fn nak_exact_bytes_single_and_range() {
        let p = pkt(ControlType::Nak(vec![
            LossRange {
                first: SeqNumber::new(5),
                last: SeqNumber::new(5),
            },
            LossRange {
                first: SeqNumber::new(100),
                last: SeqNumber::new(102),
            },
        ]));
        let mut expect = header(0x0003, 0);
        expect.extend_from_slice(&[0x00, 0x00, 0x00, 0x05]); // single, MSB=0
        expect.extend_from_slice(&[0x80, 0x00, 0x00, 0x64]); // lo=100, MSB=1
        expect.extend_from_slice(&[0x00, 0x00, 0x00, 0x66]); // hi=102, MSB=0
        assert_eq!(encode(&p), expect);
        round_trip(&p);
    }

    #[test]
    fn nak_two_packet_range_encodes_as_pair() {
        // hi = lo + 1 must still be a range pair (libsrt emits pairs for any
        // hi > lo).
        let p = pkt(ControlType::Nak(vec![LossRange {
            first: SeqNumber::new(10),
            last: SeqNumber::new(11),
        }]));
        assert_eq!(encode(&p).len(), 16 + 8);
        round_trip(&p);
    }

    #[test]
    fn nak_degenerate_range_pair_accepted() {
        // A range pair with hi == lo is legal input even though we never
        // emit it; parses to a single loss.
        let mut bytes = header(0x0003, 0);
        bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x64]);
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]);
        assert_eq!(
            ControlPacket::parse(&bytes).unwrap(),
            pkt(ControlType::Nak(vec![LossRange {
                first: SeqNumber::new(100),
                last: SeqNumber::new(100),
            }]))
        );
    }

    #[test]
    fn nak_range_across_seq_wrap_accepted() {
        // Circular compare: [0x7FFF_FFFE .. 1] is a valid 4-packet range.
        let p = pkt(ControlType::Nak(vec![LossRange {
            first: SeqNumber::new(0x7FFF_FFFE),
            last: SeqNumber::new(1),
        }]));
        round_trip(&p);
    }

    #[test]
    fn nak_rejects_lo_greater_than_hi() {
        let mut bytes = header(0x0003, 0);
        bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0xC8]); // lo = 200
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]); // hi = 100
        assert_eq!(
            ControlPacket::parse(&bytes),
            Err(PacketError::BadCif("NAK range start after end"))
        );
    }

    #[test]
    fn nak_rejects_range_missing_end() {
        let mut bytes = header(0x0003, 0);
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x05]);
        bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x64]); // lo without hi
        assert_eq!(
            ControlPacket::parse(&bytes),
            Err(PacketError::BadCif("NAK range missing end word"))
        );
    }

    #[test]
    fn nak_rejects_empty_loss_list() {
        let bytes = header(0x0003, 0);
        assert_eq!(
            ControlPacket::parse(&bytes),
            Err(PacketError::BadCif("empty NAK loss list"))
        );
    }

    // ---- DROPREQ ----

    #[test]
    fn dropreq_exact_bytes() {
        let p = pkt(ControlType::DropRequest {
            msg_number: MsgNumber::new(7),
            first: SeqNumber::new(10),
            last: SeqNumber::new(20),
        });
        let mut expect = header(0x0007, 7);
        expect.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]);
        expect.extend_from_slice(&[0x00, 0x00, 0x00, 0x14]);
        assert_eq!(encode(&p), expect);
        round_trip(&p);
    }

    #[test]
    fn dropreq_masks_message_number() {
        // Upper 6 bits of the info word carry garbage flags → masked off.
        let mut bytes = header(0x0007, 0xFC00_0007);
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]);
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x14]);
        let p = ControlPacket::parse(&bytes).unwrap();
        assert_eq!(
            p.control_type,
            ControlType::DropRequest {
                msg_number: MsgNumber::new(7),
                first: SeqNumber::new(10),
                last: SeqNumber::new(20),
            }
        );
    }

    #[test]
    fn dropreq_short_cif_rejected() {
        let mut bytes = header(0x0007, 0);
        bytes.extend_from_slice(&[0, 0, 0, 0]); // only 1 word
        assert!(matches!(
            ControlPacket::parse(&bytes),
            Err(PacketError::BadCif(_))
        ));
    }

    // ---- dispatch / errors ----

    #[test]
    fn unknown_control_type_rejected() {
        let bytes = header(0x0009, 0);
        assert_eq!(
            ControlPacket::parse(&bytes),
            Err(PacketError::UnknownControlType(0x0009))
        );
    }

    #[test]
    fn user_defined_type_reports_subtype() {
        let mut bytes = header(0x7FFF, 0);
        bytes[2] = 0x00;
        bytes[3] = 0x03; // subtype = SRT_CMD_KMREQ
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            ControlPacket::parse(&bytes),
            Err(PacketError::UnknownControlType(0x0003))
        );
    }

    #[test]
    fn truncated_header_rejected() {
        assert_eq!(
            ControlPacket::parse(&[0x80; 15]),
            Err(PacketError::TooShort)
        );
        assert_eq!(ControlPacket::parse(&[]), Err(PacketError::TooShort));
    }

    #[test]
    fn round_trip_all_variants_except_handshake() {
        let variants = vec![
            ControlType::KeepAlive,
            ControlType::Ack {
                ack_number: 0,
                cif: AckCif {
                    last_ack_seq: SeqNumber::new(9),
                    ..AckCif::default()
                },
            },
            ControlType::Ack {
                ack_number: 12,
                cif: full_ack_cif(),
            },
            ControlType::Nak(vec![
                LossRange {
                    first: SeqNumber::new(1),
                    last: SeqNumber::new(1),
                },
                LossRange {
                    first: SeqNumber::new(3),
                    last: SeqNumber::new(9),
                },
            ]),
            ControlType::CongestionWarning,
            ControlType::Shutdown,
            ControlType::AckAck {
                ack_number: 0x7FFF_FFFF,
            },
            ControlType::DropRequest {
                msg_number: MsgNumber::new(0),
                first: SeqNumber::new(55),
                last: SeqNumber::new(60),
            },
            ControlType::PeerError { code: 4000 },
        ];
        for ct in variants {
            round_trip(&pkt(ct));
        }
    }

    // ---- HANDSHAKE (cross-module: delegates to packet::handshake) ----

    use crate::packet::handshake::{
        reject,
        HandshakeType,
        HsExtFields,
        HsExtension,
        HsFlags,
        HS_EXT_CONFIG,
        HS_EXT_HSREQ,
        SRT_MAGIC,
        SRT_VERSION,
    };

    fn base_hs_cif(handshake_type: HandshakeType) -> HandshakeCif {
        HandshakeCif {
            version: 5,
            encryption: 0,
            extension_field: 0,
            initial_seq: SeqNumber::new(0x0123_4567),
            mss: 1500,
            flow_window: 8192,
            handshake_type,
            socket_id: SocketId(0x1122_3344),
            cookie: 0x0BAD_F00D,
            peer_ip: {
                let mut ip = [0u8; 16];
                ip[.. 4].copy_from_slice(&[0x01, 0x00, 0x00, 0x7F]); // 127.0.0.1 wire word
                ip
            },
            extensions: Vec::new(),
        }
    }

    #[test]
    fn handshake_conclusion_round_trip_delegates_to_cif_codec() {
        let mut cif = base_hs_cif(HandshakeType::Conclusion);
        cif.extensions = vec![
            HsExtension::HsReq(HsExtFields {
                srt_version: SRT_VERSION,
                flags: HsFlags::live_defaults(),
                recv_latency_ms: 120,
                send_latency_ms: 120,
            }),
            HsExtension::StreamId("abc".into()),
        ];
        // encode_cif derives the Extension Field from the attached blocks;
        // for parse(encode(p)) == p the stored field must match.
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_CONFIG;

        let p = pkt(ControlType::Handshake(cif.clone()));
        let bytes = encode(&p);
        // Header: type code 0x0000, Type-specific Information 0.
        assert_eq!(&bytes[.. HEADER_SIZE], &header(0x0000, 0)[..]);
        // Body is byte-identical to the handshake codec's own CIF encoding.
        let mut cif_bytes = Vec::new();
        cif.encode_cif(&mut cif_bytes);
        assert_eq!(&bytes[HEADER_SIZE ..], &cif_bytes[..]);
        round_trip(&p);
    }

    #[test]
    fn handshake_extensionless_types_round_trip() {
        // Induction response: verbatim SRT_MAGIC Extension Field, 48-byte CIF.
        let mut induction = base_hs_cif(HandshakeType::Induction);
        induction.extension_field = SRT_MAGIC;
        let p = pkt(ControlType::Handshake(induction));
        assert_eq!(encode(&p).len(), HEADER_SIZE + 48);
        round_trip(&p);

        // Induction request (version 4, Extension Field 2), agreement,
        // rejection response.
        let mut request = base_hs_cif(HandshakeType::Induction);
        request.version = 4;
        request.extension_field = 2;
        round_trip(&pkt(ControlType::Handshake(request)));
        round_trip(&pkt(ControlType::Handshake(base_hs_cif(
            HandshakeType::Agreement,
        ))));
        round_trip(&pkt(ControlType::Handshake(base_hs_cif(
            HandshakeType::Rejection(reject::ROGUE),
        ))));
    }
}
