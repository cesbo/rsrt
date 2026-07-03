//! Data packet: wire layout per docs/spec/packets.md.

use super::{
    put_u32,
    read_u32,
    types::{
        MsgNumber,
        SeqNumber,
        SocketId,
        Timestamp,
    },
    PacketError,
};

/// Packet position within a message (PP field).
///
/// Live mode always sends single-packet messages (`Only`); anything else is
/// accepted on parse but treated as a protocol anomaly by the receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketPosition {
    Middle = 0b00,
    Last = 0b01,
    First = 0b10,
    Only = 0b11,
}

impl PacketPosition {
    fn from_bits(bits: u32) -> PacketPosition {
        match bits & 0b11 {
            0b00 => PacketPosition::Middle,
            0b01 => PacketPosition::Last,
            0b10 => PacketPosition::First,
            _ => PacketPosition::Only,
        }
    }
}

/// KK field: which stream encryption key (SEK) encrypted this packet's
/// payload; `None` means cleartext.
///
/// On receive these bits select the even/odd SEK slot for HaiCrypt
/// decryption (`crypto::Crypto::decrypt`). A non-`None` value without a
/// usable key makes the packet undecryptable: it is still buffered, ACKed,
/// and advances the receive sequence, but is never delivered — no KM or
/// connection action is taken (docs/spec/encryption.md §9.4). The packet
/// layer therefore accepts every KK value; rejection here would break
/// secured connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionFlags {
    None = 0b00,
    Even = 0b01,
    Odd = 0b10,
    Both = 0b11,
}

impl EncryptionFlags {
    fn from_bits(bits: u32) -> EncryptionFlags {
        match bits & 0b11 {
            0b00 => EncryptionFlags::None,
            0b01 => EncryptionFlags::Even,
            0b10 => EncryptionFlags::Odd,
            _ => EncryptionFlags::Both,
        }
    }
}

/// SRT data packet (F bit = 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPacket {
    pub seq: SeqNumber,
    pub position: PacketPosition,
    /// O flag: in-order delivery required (live mode sets it).
    pub order: bool,
    pub encryption: EncryptionFlags,
    /// R flag: this packet is a retransmission.
    pub retransmitted: bool,
    pub msg_number: MsgNumber,
    pub timestamp: Timestamp,
    pub dst_socket_id: SocketId,
    pub payload: Vec<u8>,
}

impl DataPacket {
    /// Wire size of the data packet header.
    pub const HEADER_SIZE: usize = 16;

    /// Parses a complete data packet. The caller has already checked that
    /// the F bit (MSB of the first byte) is 0.
    pub fn parse(buf: &[u8]) -> Result<DataPacket, PacketError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(PacketError::TooShort);
        }
        let word0 = read_u32(buf, 0);
        let word1 = read_u32(buf, 4);
        tracing::trace!(
            seq = word0 & SeqNumber::MASK,
            payload_len = buf.len() - Self::HEADER_SIZE,
            "data packet parsed"
        );
        Ok(DataPacket {
            seq: SeqNumber::new(word0 & SeqNumber::MASK),
            position: PacketPosition::from_bits(word1 >> 30),
            order: word1 & 0x2000_0000 != 0,
            encryption: EncryptionFlags::from_bits(word1 >> 27),
            retransmitted: word1 & 0x0400_0000 != 0,
            msg_number: MsgNumber::new(word1 & MsgNumber::MASK),
            timestamp: Timestamp(read_u32(buf, 8)),
            dst_socket_id: SocketId(read_u32(buf, 12)),
            payload: buf[Self::HEADER_SIZE ..].to_vec(),
        })
    }

    /// Appends the encoded packet (header + payload) to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(Self::HEADER_SIZE + self.payload.len());
        // F = 0 is implied: seq is 31-bit, MSB always clear.
        put_u32(out, self.seq.value());
        let word1 = ((self.position as u32) << 30)
            | ((self.order as u32) << 29)
            | ((self.encryption as u32) << 27)
            | ((self.retransmitted as u32) << 26)
            | self.msg_number.value();
        put_u32(out, word1);
        put_u32(out, self.timestamp.0);
        put_u32(out, self.dst_socket_id.0);
        out.extend_from_slice(&self.payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DataPacket {
        DataPacket {
            seq: SeqNumber::new(0x1234_5678),
            position: PacketPosition::Only,
            order: false,
            encryption: EncryptionFlags::None,
            retransmitted: true,
            msg_number: MsgNumber::new(5),
            timestamp: Timestamp(0x0000_0100),
            dst_socket_id: SocketId(0x0000_00AB),
            payload: vec![0xDE, 0xAD],
        }
    }

    #[test]
    fn encode_exact_bytes() {
        let mut out = Vec::new();
        sample().encode(&mut out);
        // word1 = PP(11) << 30 | R(1) << 26 | msg 5 = 0xC400_0005
        assert_eq!(
            out,
            [
                0x12, 0x34, 0x56, 0x78, // seq, F = 0
                0xC4, 0x00, 0x00, 0x05, // PP=solo, R=1, msg=5
                0x00, 0x00, 0x01, 0x00, // timestamp
                0x00, 0x00, 0x00, 0xAB, // dst socket id
                0xDE, 0xAD, // payload untouched
            ]
        );
    }

    #[test]
    fn parse_exact_bytes() {
        // PP=first(10), O=1, KK=odd(10), R=0, msg = 0x03FF_FFFF (max).
        // word1 = 0x8000_0000 | 0x2000_0000 | 0x1000_0000 | 0x03FF_FFFF
        //       = 0xB3FF_FFFF
        let buf = [
            0x7F, 0xFF, 0xFF, 0xFF, // seq = 0x7FFF_FFFF (max)
            0xB3, 0xFF, 0xFF, 0xFF, // flags word
            0xFF, 0xFF, 0xFF, 0xFF, // timestamp = u32::MAX
            0x00, 0x00, 0x00, 0x01, // dst socket id 1
            0x01, 0x02, 0x03, // payload
        ];
        let p = DataPacket::parse(&buf).unwrap();
        assert_eq!(p.seq, SeqNumber::new(SeqNumber::MASK));
        assert_eq!(p.position, PacketPosition::First);
        assert!(p.order);
        assert_eq!(p.encryption, EncryptionFlags::Odd);
        assert!(!p.retransmitted);
        assert_eq!(p.msg_number, MsgNumber::new(MsgNumber::MASK));
        assert_eq!(p.timestamp, Timestamp(u32::MAX));
        assert_eq!(p.dst_socket_id, SocketId(1));
        assert_eq!(p.payload, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn round_trip_all_flag_combinations() {
        for position in [
            PacketPosition::Middle,
            PacketPosition::Last,
            PacketPosition::First,
            PacketPosition::Only,
        ] {
            for encryption in [
                EncryptionFlags::None,
                EncryptionFlags::Even,
                EncryptionFlags::Odd,
                EncryptionFlags::Both,
            ] {
                for order in [false, true] {
                    for retransmitted in [false, true] {
                        let p = DataPacket {
                            position,
                            encryption,
                            order,
                            retransmitted,
                            ..sample()
                        };
                        let mut out = Vec::new();
                        p.encode(&mut out);
                        assert_eq!(DataPacket::parse(&out).unwrap(), p);
                    }
                }
            }
        }
    }

    #[test]
    fn encrypted_kk_values_accepted_at_packet_layer() {
        // encryption.md §9.4: undecryptable packets are buffered and ACKed,
        // never rejected. The packet layer must parse every KK value; key
        // availability is the crypto layer's concern.
        for (kk_bits, expected) in [
            (0b00u32, EncryptionFlags::None),
            (0b01, EncryptionFlags::Even),
            (0b10, EncryptionFlags::Odd),
            (0b11, EncryptionFlags::Both),
        ] {
            let mut buf = Vec::new();
            sample().encode(&mut buf);
            // Patch the KK bits (word1 bits 28..27) directly in the wire image.
            buf[4] = (buf[4] & !0b0001_1000) | (kk_bits << 3) as u8;
            let p = DataPacket::parse(&buf).expect("KK must never fail parse");
            assert_eq!(p.encryption, expected);
        }
    }

    #[test]
    fn empty_payload_round_trip() {
        let p = DataPacket {
            payload: Vec::new(),
            ..sample()
        };
        let mut out = Vec::new();
        p.encode(&mut out);
        assert_eq!(out.len(), 16);
        assert_eq!(DataPacket::parse(&out).unwrap(), p);
    }

    #[test]
    fn truncated_header_rejected() {
        assert_eq!(DataPacket::parse(&[0u8; 15]), Err(PacketError::TooShort));
        assert_eq!(DataPacket::parse(&[]), Err(PacketError::TooShort));
    }

    #[test]
    fn max_payload_round_trip() {
        let p = DataPacket {
            payload: vec![0x47; 1456],
            ..sample()
        };
        let mut out = Vec::new();
        p.encode(&mut out);
        assert_eq!(out.len(), 16 + 1456);
        assert_eq!(DataPacket::parse(&out).unwrap(), p);
    }
}
