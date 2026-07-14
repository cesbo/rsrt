//! Layer 1 — packet codec.
//!
//! Pure (de)serialization of SRT wire packets. No I/O, no clocks. Every
//! packet round-trips: `parse(encode(p)) == p` — with one deliberate
//! exception: a handshake CIF's Extension Field is re-derived from the
//! attached extension blocks whenever any are present (see
//! [`HandshakeCif::encode_cif`]), so the equality holds only when
//! `extension_field` is consistent with `extensions`. A parsed CIF keeps the
//! wire field verbatim because the core listener's ROGUE validation needs
//! the raw bits. Wire reference: docs/spec/packets.md and
//! docs/spec/handshake.md.

mod control;
mod data;
mod handshake;
mod types;

use std::fmt;

use bytes::Bytes;

#[cfg(test)]
pub use self::handshake::SRT_CMD_SID;
pub use self::{
    control::{
        AckCif,
        ControlPacket,
        ControlType,
        LossRange,
    },
    data::{
        DataPacket,
        EncryptionFlags,
        PacketPosition,
    },
    handshake::{
        reject,
        HandshakeCif,
        HandshakeType,
        HsExtFields,
        HsExtension,
        HsFlags,
        HS_EXT_CONFIG,
        HS_EXT_HSREQ,
        HS_EXT_KMREQ,
        SRT_CMD_FILTER,
        SRT_CMD_GROUP,
        SRT_MAGIC,
        SRT_VERSION,
    },
    types::{
        MsgNumber,
        SeqNumber,
        SocketId,
        Timestamp,
    },
};

/// Any SRT packet, discriminated by the F bit (MSB of the first byte).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    Data(DataPacket),
    Control(ControlPacket),
}

/// Wire size of the common packet header (data and control).
pub(crate) const HEADER_SIZE: usize = 16;

/// Reads the big-endian 32-bit word at `off`. Caller guarantees bounds.
pub(crate) fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Appends `value` as a big-endian 32-bit word.
pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

impl Packet {
    /// Parses one UDP datagram payload as an SRT packet.
    pub fn parse(buf: &[u8]) -> Result<Packet, PacketError> {
        if buf.len() < HEADER_SIZE {
            return Err(PacketError::TooShort);
        }
        // F bit: MSB of the first byte. 0 = data, 1 = control.
        if buf[0] & 0x80 == 0 {
            Ok(Packet::Data(DataPacket::parse(buf)?))
        } else {
            Ok(Packet::Control(ControlPacket::parse(buf)?))
        }
    }

    /// Parses one OWNED UDP datagram as an SRT packet, slicing a data
    /// packet's payload with no copy (see [`DataPacket::parse_owned`]).
    /// Control packets decode their fields out and drop the buffer, so this is
    /// equivalent to [`Packet::parse`] for them.
    pub fn parse_owned(buf: Bytes) -> Result<Packet, PacketError> {
        if buf.len() < HEADER_SIZE {
            return Err(PacketError::TooShort);
        }
        // F bit: MSB of the first byte. 0 = data, 1 = control.
        if buf[0] & 0x80 == 0 {
            Ok(Packet::Data(DataPacket::parse_owned(buf)?))
        } else {
            Ok(Packet::Control(ControlPacket::parse(&buf)?))
        }
    }

    /// Appends the encoded packet to `out` (which is not cleared).
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Packet::Data(p) => p.encode(out),
            Packet::Control(p) => p.encode(out),
        }
    }

    #[cfg(test)]
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Packet::Data(p) => p.timestamp,
            Packet::Control(p) => p.timestamp,
        }
    }

    pub fn dst_socket_id(&self) -> SocketId {
        match self {
            Packet::Data(p) => p.dst_socket_id,
            Packet::Control(p) => p.dst_socket_id,
        }
    }
}

/// Packet (de)serialization failure. The connection layer logs and drops
/// undecodable datagrams; it never tears down a connection because of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// Datagram shorter than the layout requires.
    TooShort,
    /// Control type (or user-defined subtype) we do not implement.
    UnknownControlType(u16),
    /// Structurally invalid handshake CIF.
    BadHandshake(&'static str),
    /// Structurally invalid control CIF (ACK/NAK/DROPREQ...).
    BadCif(&'static str),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::TooShort => write!(f, "datagram too short"),
            PacketError::UnknownControlType(t) => write!(f, "unknown control type {t:#06x}"),
            PacketError::BadHandshake(msg) => write!(f, "bad handshake CIF: {msg}"),
            PacketError::BadCif(msg) => write!(f, "bad control CIF: {msg}"),
        }
    }
}

impl std::error::Error for PacketError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dispatches_on_f_bit() {
        // F = 0 → data packet (seq 1, solo, msg 1, empty payload).
        let data = [
            0x00, 0x00, 0x00, 0x01, 0xC0, 0x00, 0x00, 0x01, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        ];
        assert!(matches!(Packet::parse(&data), Ok(Packet::Data(_))));

        // F = 1 → control packet (keepalive, no pad).
        let ctrl = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        ];
        match Packet::parse(&ctrl) {
            Ok(Packet::Control(p)) => {
                assert_eq!(p.control_type, ControlType::KeepAlive);
                assert_eq!(p.dst_socket_id, SocketId(5));
            }
            other => panic!("expected control packet, got {other:?}"),
        }
    }

    #[test]
    fn parse_owned_dispatches_on_f_bit() {
        let data = [
            0x00, 0x00, 0x00, 0x01, 0xC0, 0x00, 0x00, 0x01, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        ];
        assert!(matches!(
            Packet::parse_owned(Bytes::copy_from_slice(&data)),
            Ok(Packet::Data(_))
        ));
        let ctrl = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        ];
        assert!(matches!(
            Packet::parse_owned(Bytes::copy_from_slice(&ctrl)),
            Ok(Packet::Control(_))
        ));
        assert_eq!(
            Packet::parse_owned(Bytes::from_static(&[0x80; 15])),
            Err(PacketError::TooShort)
        );
    }

    #[test]
    fn parse_rejects_short_datagram() {
        assert_eq!(Packet::parse(&[]), Err(PacketError::TooShort));
        assert_eq!(Packet::parse(&[0x80; 15]), Err(PacketError::TooShort));
    }

    #[test]
    fn packet_accessors() {
        let ctrl = [
            0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07,
        ];
        let p = Packet::parse(&ctrl).unwrap();
        assert_eq!(p.timestamp(), Timestamp(0x100));
        assert_eq!(p.dst_socket_id(), SocketId(7));
    }

    #[test]
    fn packet_round_trip() {
        let p = Packet::Control(ControlPacket {
            timestamp: Timestamp(42),
            dst_socket_id: SocketId(0xDEAD_BEEF),
            control_type: ControlType::AckAck { ack_number: 3 },
        });
        let mut out = Vec::new();
        p.encode(&mut out);
        assert_eq!(Packet::parse(&out).unwrap(), p);
    }
}
