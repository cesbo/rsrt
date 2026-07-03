//! Handshake CIF and SRT handshake extensions: docs/spec/handshake.md.

use std::net::Ipv4Addr;

use tracing::{
    trace,
    warn,
};

use super::{
    types::{
        SeqNumber,
        SocketId,
    },
    PacketError,
};

/// SRT library version we advertise in HSREQ/HSRSP (1.4.4, matching the
/// interop target).
pub const SRT_VERSION: u32 = 0x0001_0404;

/// Magic value carried in the Extension Field of the listener's INDUCTION
/// response, marking HSv5 support.
pub const SRT_MAGIC: u16 = 0x4A17;

/// Extension Field bits of the CONCLUSION handshake.
pub const HS_EXT_HSREQ: u16 = 0x1;
pub const HS_EXT_KMREQ: u16 = 0x2;
pub const HS_EXT_CONFIG: u16 = 0x4;

/// Size of the fixed part of the handshake CIF, bytes.
const CIF_SIZE: usize = 48;

/// Handshake Type field values (docs/spec/handshake.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeType {
    /// 0x00000000 — rendezvous only; parsed but always rejected.
    Waveahand,
    /// 0x00000001
    Induction,
    /// 0xFFFFFFFF (-1)
    Conclusion,
    /// 0xFFFFFFFE (-2)
    Agreement,
    /// Values >= 1000: connection rejected, code = 1000 + SRT_REJ reason.
    Rejection(u32),
}

impl HandshakeType {
    pub fn from_u32(value: u32) -> Result<HandshakeType, PacketError> {
        match value {
            0 => Ok(HandshakeType::Waveahand),
            1 => Ok(HandshakeType::Induction),
            0xFFFF_FFFF => Ok(HandshakeType::Conclusion),
            0xFFFF_FFFE => Ok(HandshakeType::Agreement),
            // Rejection codes are signed-positive (1000 + reason, plus the
            // >= 2000 server/user ranges). Negative-as-i32 values other than
            // CONCLUSION/AGREEMENT (e.g. -3 DONE) never legitimately appear
            // on the wire.
            1000 ..= 0x7FFF_FFFF => Ok(HandshakeType::Rejection(value)),
            _ => Err(PacketError::BadHandshake("unknown handshake type")),
        }
    }

    pub fn to_u32(self) -> u32 {
        match self {
            HandshakeType::Waveahand => 0,
            HandshakeType::Induction => 1,
            HandshakeType::Conclusion => 0xFFFF_FFFF,
            HandshakeType::Agreement => 0xFFFF_FFFE,
            HandshakeType::Rejection(code) => code,
        }
    }
}

/// SRT_REJ rejection reasons (handshake type = 1000 + reason).
pub mod reject {
    pub const UNKNOWN: u32 = 1000;
    pub const SYSTEM: u32 = 1001;
    pub const PEER: u32 = 1002;
    pub const RESOURCE: u32 = 1003;
    pub const ROGUE: u32 = 1004;
    pub const BACKLOG: u32 = 1005;
    pub const IPE: u32 = 1006;
    pub const CLOSE: u32 = 1007;
    pub const VERSION: u32 = 1008;
    pub const RDVCOOKIE: u32 = 1009;
    pub const BADSECRET: u32 = 1010;
    pub const UNSECURE: u32 = 1011;
    pub const MESSAGEAPI: u32 = 1012;
    pub const CONGESTION: u32 = 1013;
    pub const FILTER: u32 = 1014;
    pub const GROUP: u32 = 1015;
    pub const TIMEOUT: u32 = 1016;
}

/// Handshake Control Information Field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeCif {
    /// 4 in the caller's INDUCTION request, 5 everywhere else in HSv5.
    pub version: u32,
    /// Encryption Field: 0 = no advertised cipher (the only value we send).
    pub encryption: u16,
    /// Extension Field: HS_EXT_* bits in CONCLUSION, `SRT_MAGIC` in the
    /// listener's INDUCTION response, 2 in the caller's INDUCTION request.
    pub extension_field: u16,
    pub initial_seq: SeqNumber,
    /// MTU size, default 1500.
    pub mss: u32,
    /// Maximum flow window, default 8192.
    pub flow_window: u32,
    pub handshake_type: HandshakeType,
    /// The *sender's* SRT socket id.
    pub socket_id: SocketId,
    pub cookie: u32,
    /// Peer (destination) IP address; see docs/spec/handshake.md for the
    /// exact word/byte ordering. Use [`HandshakeCif::encode_peer_ip`].
    pub peer_ip: [u8; 16],
    pub extensions: Vec<HsExtension>,
}

impl HandshakeCif {
    /// Parses the handshake CIF (everything after the 16-byte packet header).
    pub fn parse_cif(buf: &[u8]) -> Result<HandshakeCif, PacketError> {
        if buf.len() < CIF_SIZE {
            return Err(PacketError::TooShort);
        }
        let isn = read_u32(buf, 8);
        // `CHandShake::valid()` requires 0 <= ISN < 0x7FFF_FFFF — the max
        // sequence number itself (== `SeqNumber::MASK`) is excluded, and a
        // 32nd bit is not representable in SeqNumber. Enforce the full bound
        // here instead of silently masking. libsrt runs valid() only on
        // CONCLUSION; applying it to every handshake type is harmless (a
        // caller with ISN == max is doomed at the conclusion stage anyway).
        if isn >= SeqNumber::MASK {
            return Err(PacketError::BadHandshake("ISN outside valid range"));
        }
        let handshake_type = HandshakeType::from_u32(read_u32(buf, 20))?;
        let mut peer_ip = [0u8; 16];
        peer_ip.copy_from_slice(&buf[32 .. 48]);
        let extensions = parse_extensions(&buf[CIF_SIZE ..])?;
        let cif = HandshakeCif {
            version: read_u32(buf, 0),
            encryption: read_u16(buf, 4),
            extension_field: read_u16(buf, 6),
            initial_seq: SeqNumber::new(isn),
            mss: read_u32(buf, 12),
            flow_window: read_u32(buf, 16),
            handshake_type,
            socket_id: SocketId(read_u32(buf, 24)),
            cookie: read_u32(buf, 28),
            peer_ip,
            extensions,
        };
        trace!(
            hs_type = ?cif.handshake_type,
            version = cif.version,
            extensions = cif.extensions.len(),
            "parsed handshake CIF"
        );
        Ok(cif)
    }

    /// Appends the encoded CIF (with extensions) to `out`.
    ///
    /// When extension blocks are attached, the Extension Field is derived
    /// from the blocks themselves ([`HandshakeCif::extension_bits`]) — a
    /// stale `extension_field` cannot produce the bit-without-block /
    /// block-without-bit mismatches libsrt rejects as ROGUE. With no blocks,
    /// `extension_field` is written verbatim (INDUCTION `2` / `SRT_MAGIC`,
    /// rejection-response echo).
    pub fn encode_cif(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.encryption.to_be_bytes());
        let ext_field = if self.extensions.is_empty() {
            self.extension_field
        } else {
            self.extension_bits()
        };
        out.extend_from_slice(&ext_field.to_be_bytes());
        out.extend_from_slice(&self.initial_seq.value().to_be_bytes());
        out.extend_from_slice(&self.mss.to_be_bytes());
        out.extend_from_slice(&self.flow_window.to_be_bytes());
        out.extend_from_slice(&self.handshake_type.to_u32().to_be_bytes());
        out.extend_from_slice(&self.socket_id.0.to_be_bytes());
        out.extend_from_slice(&self.cookie.to_be_bytes());
        out.extend_from_slice(&self.peer_ip);
        for ext in &self.extensions {
            ext.encode(out);
        }
    }

    /// Extension Field bits implied by the attached extension blocks.
    pub fn extension_bits(&self) -> u16 {
        let mut bits = 0;
        for ext in &self.extensions {
            bits |= match ext {
                HsExtension::HsReq(_) | HsExtension::HsRsp(_) => HS_EXT_HSREQ,
                HsExtension::KmReq(_) | HsExtension::KmRsp(_) => HS_EXT_KMREQ,
                HsExtension::StreamId(_)
                | HsExtension::Congestion(_)
                | HsExtension::Unknown { .. } => HS_EXT_CONFIG,
                // Never sent by us; the mapping keeps a re-encoded *parsed*
                // CIF (e.g. one carrying a short HSREQ) byte-faithful.
                HsExtension::Invalid { cmd, .. } => match *cmd {
                    SRT_CMD_HSREQ | SRT_CMD_HSRSP => HS_EXT_HSREQ,
                    SRT_CMD_KMREQ | SRT_CMD_KMRSP => HS_EXT_KMREQ,
                    _ => HS_EXT_CONFIG,
                },
            };
        }
        bits
    }

    /// Builds the 16-byte Peer IP field from an IPv4 address.
    ///
    /// Word 0 carries the address with its bytes reversed (per-word
    /// little-endian rule, docs/spec/handshake.md §2.2); words 1..3 are zero.
    pub fn encode_peer_ip(addr: Ipv4Addr) -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut octets = addr.octets();
        octets.reverse();
        out[.. 4].copy_from_slice(&octets);
        out
    }

    /// Convenience: the first HSREQ/HSRSP extension, if present.
    pub fn hs_ext(&self) -> Option<&HsExtFields> {
        self.extensions.iter().find_map(|e| match e {
            HsExtension::HsReq(f) | HsExtension::HsRsp(f) => Some(f),
            _ => None,
        })
    }

    /// Convenience: the StreamID extension, if present.
    pub fn stream_id(&self) -> Option<&str> {
        self.extensions.iter().find_map(|e| match e {
            HsExtension::StreamId(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// True if the peer attached key material (encryption requested).
    pub fn requests_encryption(&self) -> bool {
        self.encryption != 0
            || self
                .extensions
                .iter()
                .any(|e| matches!(e, HsExtension::KmReq(_) | HsExtension::KmRsp(_)))
    }
}

/// Extension command codes.
pub const SRT_CMD_HSREQ: u16 = 1;
pub const SRT_CMD_HSRSP: u16 = 2;
pub const SRT_CMD_KMREQ: u16 = 3;
pub const SRT_CMD_KMRSP: u16 = 4;
pub const SRT_CMD_SID: u16 = 5;
pub const SRT_CMD_CONGESTION: u16 = 6;
// FILTER/GROUP have no HsExtension variant (they arrive as `Unknown`); the
// codes exist for the layers that inspect `Unknown { cmd, .. }`.
pub const SRT_CMD_FILTER: u16 = 7;
pub const SRT_CMD_GROUP: u16 = 8;

/// A handshake extension block (16-bit command, 16-bit length in 4-byte
/// words, payload).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HsExtension {
    HsReq(HsExtFields),
    HsRsp(HsExtFields),
    /// StreamID, wire-encoded with byte-reversed 32-bit words
    /// (docs/spec/handshake.md §4.4). Max 512 bytes on the wire.
    ///
    /// libsrt treats the content as an *arbitrary byte string* (non-UTF-8 is
    /// legal and accepted by a 1.4.4 peer); this String-typed codec decodes
    /// it with `String::from_utf8_lossy`, so a non-UTF-8 SID still connects
    /// but is surfaced with U+FFFD replacement characters (a deliberate,
    /// documented lossy conversion — distinct raw SIDs may collide).
    StreamId(String),
    /// Key material — opaque: kept only so an unencrypted implementation can
    /// detect and reject encrypted peers.
    KmReq(Vec<u8>),
    KmRsp(Vec<u8>),
    /// Congestion controller name ("live" is the implied default). Decoded
    /// lossily like [`HsExtension::StreamId`]; a non-UTF-8 name can never
    /// equal `"live"`, so it naturally hits the CONGESTION rejection path.
    Congestion(String),
    /// A recognized command whose *content* failed validation (SID length
    /// 0/>512, HSREQ/HSRSP shorter than 3 words). Content-level problems are
    /// deliberately non-fatal at the codec layer: libsrt validates extension
    /// content only in `interpretSrtHandshake`, *after* the listener's
    /// cookie check, and answers with a rejection — a parse failure here
    /// would instead drop the datagram before core ever sees it, giving the
    /// caller a silent 3 s timeout. The core layer must answer ROGUE when it
    /// meets this marker. Raw wire content is preserved for round-tripping.
    Invalid {
        cmd: u16,
        data: Vec<u8>,
    },
    Unknown {
        cmd: u16,
        data: Vec<u8>,
    },
}

impl HsExtension {
    fn encode(&self, out: &mut Vec<u8>) {
        let mut content = Vec::new();
        let cmd = match self {
            HsExtension::HsReq(f) => {
                f.encode(&mut content);
                SRT_CMD_HSREQ
            }
            HsExtension::HsRsp(f) => {
                f.encode(&mut content);
                SRT_CMD_HSRSP
            }
            HsExtension::StreamId(s) => {
                debug_assert!(
                    !s.is_empty() && s.len() <= 512,
                    "stream id length out of range"
                );
                pack_string_words(s, &mut content);
                SRT_CMD_SID
            }
            HsExtension::KmReq(data) => {
                content.extend_from_slice(data);
                SRT_CMD_KMREQ
            }
            HsExtension::KmRsp(data) => {
                content.extend_from_slice(data);
                SRT_CMD_KMRSP
            }
            HsExtension::Congestion(s) => {
                pack_string_words(s, &mut content);
                SRT_CMD_CONGESTION
            }
            HsExtension::Invalid { cmd, data } | HsExtension::Unknown { cmd, data } => {
                content.extend_from_slice(data);
                *cmd
            }
        };
        // KM/unknown payloads come from the wire and are already whole
        // words; pad defensively so the length field stays truthful.
        while content.len() % 4 != 0 {
            content.push(0);
        }
        debug_assert!(content.len() / 4 <= u16::MAX as usize);
        out.extend_from_slice(&cmd.to_be_bytes());
        out.extend_from_slice(&((content.len() / 4) as u16).to_be_bytes());
        out.extend_from_slice(&content);
    }
}

/// Payload of HSREQ/HSRSP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HsExtFields {
    /// SRT library version, e.g. [`SRT_VERSION`].
    pub srt_version: u32,
    pub flags: HsFlags,
    /// TSBPD delay for the direction the *receiver* of this extension sends
    /// data in, ms. See docs/spec/handshake.md for exact half-word layout.
    pub recv_latency_ms: u16,
    pub send_latency_ms: u16,
}

impl HsExtFields {
    fn parse(content: &[u8]) -> Result<HsExtFields, PacketError> {
        if content.len() < 12 {
            return Err(PacketError::BadHandshake(
                "HSREQ/HSRSP shorter than 3 words",
            ));
        }
        if content.len() > 12 {
            warn!(
                len = content.len(),
                "HSREQ/HSRSP longer than 3 words, extra ignored"
            );
        }
        let latency = read_u32(content, 8);
        Ok(HsExtFields {
            srt_version: read_u32(content, 0),
            flags: HsFlags(read_u32(content, 4)),
            // Receiver delay = upper half-word (first on the wire), sender
            // delay = lower half-word. Swapping negotiates the wrong
            // direction's latency.
            recv_latency_ms: (latency >> 16) as u16,
            send_latency_ms: latency as u16,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.srt_version.to_be_bytes());
        out.extend_from_slice(&self.flags.0.to_be_bytes());
        let latency = (u32::from(self.recv_latency_ms) << 16) | u32::from(self.send_latency_ms);
        out.extend_from_slice(&latency.to_be_bytes());
    }
}

/// SRT flags of HSREQ/HSRSP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HsFlags(pub u32);

impl HsFlags {
    pub const TSBPDSND: u32 = 0x01;
    pub const TSBPDRCV: u32 = 0x02;
    pub const CRYPT: u32 = 0x04;
    pub const TLPKTDROP: u32 = 0x08;
    pub const PERIODICNAK: u32 = 0x10;
    pub const REXMITFLG: u32 = 0x20;
    /// File/stream mode marker — must NOT be set in live mode.
    pub const STREAM: u32 = 0x40;
    pub const PACKET_FILTER: u32 = 0x80;

    pub fn contains(self, bits: u32) -> bool {
        self.0 & bits == bits
    }

    /// The flag set a live-mode endpoint sends (docs/spec/handshake.md §4.1):
    /// `0x3F`. CRYPT is a mandatory legacy capability bit ("understands the
    /// KK field") even for an unencrypted endpoint. STREAM must stay clear
    /// (live = message API; the peer checks it for equality). PACKET_FILTER
    /// stays clear — we have no filter support, and not advertising it keeps
    /// a libsrt peer from attaching a FILTER config block.
    pub fn live_defaults() -> HsFlags {
        HsFlags(
            Self::TSBPDSND
                | Self::TSBPDRCV
                | Self::CRYPT
                | Self::TLPKTDROP
                | Self::PERIODICNAK
                | Self::REXMITFLG,
        )
    }
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off .. off + 4].try_into().unwrap())
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(buf[off .. off + 2].try_into().unwrap())
}

fn parse_extensions(mut buf: &[u8]) -> Result<Vec<HsExtension>, PacketError> {
    let mut extensions = Vec::new();
    while buf.len() >= 4 {
        let cmd = read_u16(buf, 0);
        let content_len = read_u16(buf, 2) as usize * 4;
        if buf.len() - 4 < content_len {
            return Err(PacketError::BadHandshake("truncated extension block"));
        }
        extensions.push(parse_extension(cmd, &buf[4 .. 4 + content_len]));
        buf = &buf[4 + content_len ..];
    }
    if !buf.is_empty() {
        // libsrt sizes the extension region in whole 32-bit words; 1-3
        // stray trailing bytes after the last block are ignored, not fatal.
        warn!(
            len = buf.len(),
            "trailing bytes after extension blocks ignored"
        );
    }
    Ok(extensions)
}

/// Decodes one extension block. Content-level malformations degrade to
/// [`HsExtension::Invalid`] instead of failing the whole CIF: the listener
/// must answer them with a ROGUE rejection after the cookie check (like
/// libsrt's `interpretSrtHandshake`), which requires the CIF to parse.
fn parse_extension(cmd: u16, content: &[u8]) -> HsExtension {
    match cmd {
        SRT_CMD_HSREQ | SRT_CMD_HSRSP => match HsExtFields::parse(content) {
            Ok(fields) if cmd == SRT_CMD_HSREQ => HsExtension::HsReq(fields),
            Ok(fields) => HsExtension::HsRsp(fields),
            Err(e) => {
                warn!(cmd, len = content.len(), %e, "malformed HSREQ/HSRSP kept as invalid block");
                HsExtension::Invalid {
                    cmd,
                    data: content.to_vec(),
                }
            }
        },
        SRT_CMD_KMREQ => HsExtension::KmReq(content.to_vec()),
        SRT_CMD_KMRSP => HsExtension::KmRsp(content.to_vec()),
        SRT_CMD_SID => {
            if content.is_empty() || content.len() > 512 {
                warn!(
                    len = content.len(),
                    "stream id length out of range; kept as invalid block"
                );
                return HsExtension::Invalid {
                    cmd,
                    data: content.to_vec(),
                };
            }
            // Arbitrary byte string on the wire (docs/spec/handshake.md
            // §4.4); decoded lossily — see the StreamId variant docs.
            let sid = String::from_utf8_lossy(&unpack_bytes_words(content)).into_owned();
            HsExtension::StreamId(sid)
        }
        SRT_CMD_CONGESTION => {
            let name = String::from_utf8_lossy(&unpack_bytes_words(content)).into_owned();
            HsExtension::Congestion(name)
        }
        _ => {
            // FILTER/GROUP land here too: preserved opaquely, the core layer
            // decides whether to reject (FILTER) or skip (GROUP).
            trace!(
                cmd,
                len = content.len(),
                "unknown handshake extension preserved"
            );
            HsExtension::Unknown {
                cmd,
                data: content.to_vec(),
            }
        }
    }
}

/// Packs a string into 32-bit words, NUL-padded, with each word's bytes
/// reversed on the wire (docs/spec/handshake.md §4.4: "abcdefg" ->
/// "dcba\0gfe").
fn pack_string_words(s: &str, out: &mut Vec<u8>) {
    for chunk in s.as_bytes().chunks(4) {
        let mut word = [0u8; 4];
        word[.. chunk.len()].copy_from_slice(chunk);
        word.reverse();
        out.extend_from_slice(&word);
    }
}

/// Inverse of [`pack_string_words`]: un-reverses each 32-bit word and trims
/// trailing NUL padding. Returns raw bytes — the wire content is an
/// arbitrary byte string, not necessarily UTF-8. `content` is whole words by
/// construction of the TLV length field.
fn unpack_bytes_words(content: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(content.len());
    for chunk in content.chunks(4) {
        let mut word = [0u8; 4];
        word[.. chunk.len()].copy_from_slice(chunk);
        word.reverse();
        bytes.extend_from_slice(&word);
    }
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(cif: &HandshakeCif) -> Vec<u8> {
        let mut out = Vec::new();
        cif.encode_cif(&mut out);
        out
    }

    fn roundtrip(cif: &HandshakeCif) {
        assert_eq!(&HandshakeCif::parse_cif(&encoded(cif)).unwrap(), cif);
    }

    // -- Handshake Type mapping ------------------------------------------

    #[test]
    fn handshake_type_mapping() {
        let cases = [
            (0u32, HandshakeType::Waveahand),
            (1, HandshakeType::Induction),
            (0xFFFF_FFFF, HandshakeType::Conclusion),
            (0xFFFF_FFFE, HandshakeType::Agreement),
            (1000, HandshakeType::Rejection(reject::UNKNOWN)),
            (1004, HandshakeType::Rejection(reject::ROGUE)),
            (1008, HandshakeType::Rejection(reject::VERSION)),
            (1011, HandshakeType::Rejection(reject::UNSECURE)),
            (1016, HandshakeType::Rejection(reject::TIMEOUT)),
            (2042, HandshakeType::Rejection(2042)), // server-defined range
            (3007, HandshakeType::Rejection(3007)), // user-defined range
        ];
        for (wire, expected) in cases {
            assert_eq!(HandshakeType::from_u32(wire).unwrap(), expected);
            assert_eq!(expected.to_u32(), wire);
        }
    }

    #[test]
    fn handshake_type_rejects_unknown_values() {
        for wire in [2u32, 3, 999, 0xFFFF_FFFD /* DONE */, 0x8000_0000] {
            assert_eq!(
                HandshakeType::from_u32(wire),
                Err(PacketError::BadHandshake("unknown handshake type")),
                "value {wire:#x}"
            );
        }
    }

    // -- Peer IP ----------------------------------------------------------

    #[test]
    fn peer_ip_worked_example() {
        // Spec §2.2: 192.168.1.10 -> 0A 01 A8 C0 + 12 zero bytes.
        let field = HandshakeCif::encode_peer_ip(Ipv4Addr::new(192, 168, 1, 10));
        let mut expected = [0u8; 16];
        expected[.. 4].copy_from_slice(&[0x0A, 0x01, 0xA8, 0xC0]);
        assert_eq!(field, expected);
    }

    // -- Byte-exact CIF vectors (spec §5 field tables) ---------------------

    fn induction_request() -> HandshakeCif {
        HandshakeCif {
            version: 4,
            encryption: 0,
            extension_field: 2,
            initial_seq: SeqNumber::new(0x1234_5678),
            mss: 1500,
            flow_window: 8192,
            handshake_type: HandshakeType::Induction,
            socket_id: SocketId(0x0102_0304),
            cookie: 0,
            peer_ip: HandshakeCif::encode_peer_ip(Ipv4Addr::new(192, 168, 1, 10)),
            extensions: vec![],
        }
    }

    const INDUCTION_REQUEST_BYTES: [u8; 48] = [
        0x00, 0x00, 0x00, 0x04, // version 4
        0x00, 0x00, 0x00, 0x02, // encryption 0 | extension field 2 (UDT_DGRAM)
        0x12, 0x34, 0x56, 0x78, // ISN
        0x00, 0x00, 0x05, 0xDC, // MSS 1500
        0x00, 0x00, 0x20, 0x00, // flow window 8192
        0x00, 0x00, 0x00, 0x01, // INDUCTION
        0x01, 0x02, 0x03, 0x04, // caller socket id
        0x00, 0x00, 0x00, 0x00, // cookie 0
        0x0A, 0x01, 0xA8, 0xC0, // peer IP 192.168.1.10, per-word reversed
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn induction_request_byte_exact() {
        let cif = induction_request();
        assert_eq!(encoded(&cif), INDUCTION_REQUEST_BYTES);
        roundtrip(&cif);
    }

    #[test]
    fn induction_response_byte_exact() {
        // Listener echoes everything, changing only Version, Extension Field
        // (magic) and Cookie; CIF socket id stays the *caller's* (spec §5.2).
        let cif = HandshakeCif {
            version: 5,
            extension_field: SRT_MAGIC,
            cookie: 0x6BEE_F00D,
            ..induction_request()
        };
        let mut expected = INDUCTION_REQUEST_BYTES;
        expected[3] = 0x05; // version 5
        expected[6] = 0x4A; // magic 0x4A17
        expected[7] = 0x17;
        expected[28 .. 32].copy_from_slice(&[0x6B, 0xEE, 0xF0, 0x0D]);
        assert_eq!(encoded(&cif), expected);
        roundtrip(&cif);
    }

    fn conclusion_request() -> HandshakeCif {
        HandshakeCif {
            version: 5,
            encryption: 0,
            extension_field: HS_EXT_HSREQ | HS_EXT_CONFIG,
            initial_seq: SeqNumber::new(0x1234_5678),
            mss: 1500,
            flow_window: 8192,
            handshake_type: HandshakeType::Conclusion,
            socket_id: SocketId(0x0102_0304),
            cookie: 0x6BEE_F00D, // echoed induction cookie
            peer_ip: HandshakeCif::encode_peer_ip(Ipv4Addr::new(192, 168, 1, 10)),
            extensions: vec![
                HsExtension::HsReq(HsExtFields {
                    srt_version: SRT_VERSION,
                    flags: HsFlags::live_defaults(),
                    recv_latency_ms: 120,
                    send_latency_ms: 0,
                }),
                HsExtension::StreamId("abcdefg".to_string()),
            ],
        }
    }

    #[rustfmt::skip]
    const CONCLUSION_REQUEST_BYTES: [u8; 76] = [
        0x00, 0x00, 0x00, 0x05, // version 5
        0x00, 0x00, 0x00, 0x05, // encryption 0 | ext field HSREQ|CONFIG
        0x12, 0x34, 0x56, 0x78, // ISN (same as induction)
        0x00, 0x00, 0x05, 0xDC, // MSS 1500
        0x00, 0x00, 0x20, 0x00, // flow window 8192
        0xFF, 0xFF, 0xFF, 0xFF, // CONCLUSION
        0x01, 0x02, 0x03, 0x04, // caller socket id
        0x6B, 0xEE, 0xF0, 0x0D, // echoed cookie
        0x0A, 0x01, 0xA8, 0xC0, // listener address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // HSREQ extension
        0x00, 0x01, 0x00, 0x03, // cmd 1 (HSREQ), 3 words
        0x00, 0x01, 0x04, 0x04, // SRT version 1.4.4
        0x00, 0x00, 0x00, 0x3F, // flags: live defaults
        0x00, 0x78, 0x00, 0x00, // rcv latency 120 (upper) | snd latency 0 (lower)
        // SID extension — worked example "abcdefg" -> "dcba\0gfe"
        0x00, 0x05, 0x00, 0x02, // cmd 5 (SID), 2 words
        0x64, 0x63, 0x62, 0x61, // "dcba"
        0x00, 0x67, 0x66, 0x65, // "\0gfe"
    ];

    #[test]
    fn conclusion_request_byte_exact() {
        let cif = conclusion_request();
        assert_eq!(encoded(&cif), CONCLUSION_REQUEST_BYTES);
        roundtrip(&cif);
    }

    #[test]
    fn conclusion_response_byte_exact() {
        let cif = HandshakeCif {
            version: 5,
            encryption: 0,
            extension_field: HS_EXT_HSREQ,
            initial_seq: SeqNumber::new(0x1234_5678), // caller's ISN echoed
            mss: 1500,                                // min(caller, listener)
            flow_window: 8192,
            handshake_type: HandshakeType::Conclusion,
            socket_id: SocketId(0x00A1_B2C3), // accepted socket id
            cookie: 0x6BEE_F00D,              // echoed
            peer_ip: HandshakeCif::encode_peer_ip(Ipv4Addr::new(10, 0, 0, 2)),
            extensions: vec![HsExtension::HsRsp(HsExtFields {
                srt_version: SRT_VERSION,
                flags: HsFlags::live_defaults(),
                recv_latency_ms: 120,
                send_latency_ms: 120,
            })],
        };
        #[rustfmt::skip]
        let expected: [u8; 64] = [
            0x00, 0x00, 0x00, 0x05, // version 5
            0x00, 0x00, 0x00, 0x01, // encryption 0 | ext field HSREQ
            0x12, 0x34, 0x56, 0x78, // caller's ISN echoed
            0x00, 0x00, 0x05, 0xDC, // negotiated MSS
            0x00, 0x00, 0x20, 0x00, // flow window 8192
            0xFF, 0xFF, 0xFF, 0xFF, // CONCLUSION
            0x00, 0xA1, 0xB2, 0xC3, // accepted socket id
            0x6B, 0xEE, 0xF0, 0x0D, // echoed cookie
            0x02, 0x00, 0x00, 0x0A, // caller address 10.0.0.2, reversed
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // HSRSP extension
            0x00, 0x02, 0x00, 0x03, // cmd 2 (HSRSP), 3 words
            0x00, 0x01, 0x04, 0x04, // SRT version 1.4.4
            0x00, 0x00, 0x00, 0x3F, // flags
            0x00, 0x78, 0x00, 0x78, // rcv latency 120 | snd latency 120
        ];
        assert_eq!(encoded(&cif), expected);
        roundtrip(&cif);
    }

    #[test]
    fn rejection_response_byte_exact() {
        // Rejection = received CONCLUSION CIF echoed with only the type
        // replaced and extensions stripped (spec §3.1).
        let cif = HandshakeCif {
            handshake_type: HandshakeType::Rejection(reject::UNSECURE),
            extensions: vec![],
            ..conclusion_request()
        };
        let out = encoded(&cif);
        assert_eq!(out.len(), 48);
        assert_eq!(&out[20 .. 24], &[0x00, 0x00, 0x03, 0xF3]); // 1011
        roundtrip(&cif);
    }

    // -- Latency half-words ------------------------------------------------

    #[test]
    fn latency_halfword_order() {
        let fields = HsExtFields {
            srt_version: SRT_VERSION,
            flags: HsFlags::live_defaults(),
            recv_latency_ms: 0x1234,
            send_latency_ms: 0x5678,
        };
        let mut content = Vec::new();
        fields.encode(&mut content);
        // Receiver delay first on the wire (upper half-word).
        assert_eq!(&content[8 .. 12], &[0x12, 0x34, 0x56, 0x78]);
        let parsed = HsExtFields::parse(&content).unwrap();
        assert_eq!(parsed.recv_latency_ms, 0x1234);
        assert_eq!(parsed.send_latency_ms, 0x5678);
    }

    // -- StreamID shuffle ---------------------------------------------------

    #[test]
    fn sid_worked_examples() {
        let mut content = Vec::new();
        pack_string_words("abcdefg", &mut content);
        assert_eq!(content, b"dcba\0gfe");
        assert_eq!(unpack_bytes_words(&content), b"abcdefg");

        content.clear();
        pack_string_words("STREAM", &mut content);
        assert_eq!(content, b"ERTS\0\0MA");
        assert_eq!(unpack_bytes_words(&content), b"STREAM");
    }

    #[test]
    fn sid_exact_multiple_of_four() {
        let mut content = Vec::new();
        pack_string_words("abcd", &mut content);
        assert_eq!(content, b"dcba"); // no padding word added
        assert_eq!(unpack_bytes_words(&content), b"abcd");
    }

    #[test]
    fn sid_max_length_roundtrip() {
        let sid = "x".repeat(512);
        let cif = HandshakeCif {
            extensions: vec![
                HsExtension::HsReq(HsExtFields {
                    srt_version: SRT_VERSION,
                    flags: HsFlags::live_defaults(),
                    recv_latency_ms: 120,
                    send_latency_ms: 0,
                }),
                HsExtension::StreamId(sid.clone()),
            ],
            ..conclusion_request()
        };
        let parsed = HandshakeCif::parse_cif(&encoded(&cif)).unwrap();
        assert_eq!(parsed.stream_id(), Some(sid.as_str()));
    }

    #[test]
    fn congestion_string_shuffled() {
        let cif = HandshakeCif {
            extension_field: HS_EXT_CONFIG,
            extensions: vec![HsExtension::Congestion("live".to_string())],
            ..conclusion_request()
        };
        let out = encoded(&cif);
        assert_eq!(&out[48 .. 52], &[0x00, 0x06, 0x00, 0x01]);
        assert_eq!(&out[52 .. 56], b"evil"); // "live" per-word reversed
        roundtrip(&cif);
    }

    // -- KM and unknown extensions -------------------------------------------

    #[test]
    fn km_passthrough_opaque() {
        let km: Vec<u8> = (0 .. 16).collect();
        let cif = HandshakeCif {
            extensions: vec![
                HsExtension::HsReq(HsExtFields {
                    srt_version: SRT_VERSION,
                    flags: HsFlags::live_defaults(),
                    recv_latency_ms: 120,
                    send_latency_ms: 0,
                }),
                HsExtension::KmReq(km.clone()),
            ],
            ..conclusion_request()
        };
        let out = encoded(&cif);
        // Ext field must carry HSREQ|KMREQ.
        assert_eq!(&out[6 .. 8], &[0x00, 0x03]);
        // KM bytes appear on the wire in natural order (no per-word shuffle).
        assert_eq!(&out[64 .. 68], &[0x00, 0x03, 0x00, 0x04]); // cmd 3, 4 words
        assert_eq!(&out[68 .. 84], &km[..]);
        let parsed = HandshakeCif::parse_cif(&out).unwrap();
        assert!(parsed.requests_encryption());
        assert_eq!(parsed.extensions[1], HsExtension::KmReq(km));
    }

    #[test]
    fn km_content_is_raw_bytes_not_word_swapped() {
        // encryption.md §5 [wire-verified]: the KM blob is a natural-order
        // byte string on the wire (libsrt pre-swaps it so the channel's
        // per-word swap cancels out). It must appear byte-identical and
        // contiguous in the encoded CIF — never per-word reversed the way
        // StreamID content is (§15 trap: mixing these up shifts every KM
        // field by a reversal).
        let mut km = vec![
            0x12, 0x20, 0x29, 0x01, // KM header: even key (encryption.md §3)
            0x00, 0x00, 0x00, 0x00, // KEKI
            0x02, 0x00, 0x02, 0x00, // AES-CTR, no auth, TSSRT
            0x00, 0x00, 0x04, 0x04, // SLen/4 = 4, KLen/4 = 4
        ];
        km.extend(0xA0 .. 0xB0); // salt
        km.extend(0x30 .. 0x48); // wrap: 8 B ICV + 16 B key
        assert_eq!(km.len(), 56);
        let swapped: Vec<u8> = km
            .chunks(4)
            .flat_map(|word| word.iter().rev().copied())
            .collect();
        assert_ne!(swapped, km, "test vector must not be reversal-invariant");

        for ext in [
            HsExtension::KmReq(km.clone()),
            HsExtension::KmRsp(km.clone()),
        ] {
            let cmd = match ext {
                HsExtension::KmReq(_) => SRT_CMD_KMREQ,
                _ => SRT_CMD_KMRSP,
            };
            let cif = HandshakeCif {
                extensions: vec![
                    HsExtension::HsReq(HsExtFields {
                        srt_version: SRT_VERSION,
                        flags: HsFlags::live_defaults(),
                        recv_latency_ms: 120,
                        send_latency_ms: 0,
                    }),
                    ext.clone(),
                ],
                ..conclusion_request()
            };
            let out = encoded(&cif);
            // TLV header after the 48-byte CIF + 16-byte HSREQ block.
            assert_eq!(out.len(), 124, "cmd {cmd}");
            assert_eq!(&out[64 .. 66], &cmd.to_be_bytes(), "cmd {cmd}");
            assert_eq!(&out[66 .. 68], &[0x00, 0x0E], "cmd {cmd}"); // 14 words
            // The blob's exact bytes, contiguous and in natural order.
            assert_eq!(&out[68 .. 124], &km[..], "cmd {cmd}");
            // The word-swapped form appears nowhere in the encoding.
            assert!(
                !out.windows(swapped.len()).any(|w| w == &swapped[..]),
                "cmd {cmd}: KM content was per-word swapped"
            );
            // Parse hands the same bytes back unchanged.
            let parsed = HandshakeCif::parse_cif(&out).unwrap();
            assert_eq!(parsed.extensions[1], ext, "cmd {cmd}");
        }
    }

    #[test]
    fn unknown_extension_preserved() {
        let cif = HandshakeCif {
            extensions: vec![
                HsExtension::HsReq(HsExtFields {
                    srt_version: SRT_VERSION,
                    flags: HsFlags::live_defaults(),
                    recv_latency_ms: 120,
                    send_latency_ms: 0,
                }),
                HsExtension::Unknown {
                    cmd: SRT_CMD_FILTER,
                    data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
            ],
            ..conclusion_request()
        };
        roundtrip(&cif);
        // FILTER counts as a CONFIG-group block.
        assert_eq!(cif.extension_bits(), HS_EXT_HSREQ | HS_EXT_CONFIG);
    }

    // -- Extension Field consistency ------------------------------------------

    #[test]
    fn encoder_derives_ext_field_from_blocks() {
        // A stale/zero extension_field must not leak onto the wire when
        // blocks are attached.
        let mut cif = conclusion_request();
        cif.extension_field = 0;
        cif.extensions.push(HsExtension::KmReq(vec![0; 8]));
        let out = encoded(&cif);
        assert_eq!(
            &out[6 .. 8],
            &(HS_EXT_HSREQ | HS_EXT_KMREQ | HS_EXT_CONFIG).to_be_bytes()
        );

        // ...and bogus extra bits are dropped.
        let mut cif = conclusion_request();
        cif.extension_field = 0xFFFF;
        cif.extensions = vec![HsExtension::HsRsp(HsExtFields {
            srt_version: SRT_VERSION,
            flags: HsFlags::live_defaults(),
            recv_latency_ms: 120,
            send_latency_ms: 120,
        })];
        assert_eq!(&encoded(&cif)[6 .. 8], &HS_EXT_HSREQ.to_be_bytes());
    }

    #[test]
    fn encoder_keeps_ext_field_without_blocks() {
        // INDUCTION response magic and rejection-response echo pass through.
        let cif = HandshakeCif {
            extension_field: SRT_MAGIC,
            ..induction_request()
        };
        assert_eq!(&encoded(&cif)[6 .. 8], &SRT_MAGIC.to_be_bytes());
    }

    #[test]
    fn ext_field_rederivation_is_an_intentional_round_trip_exception() {
        // Pins the one documented exception to the crate's
        // `parse(encode(p)) == p` invariant (src/packet/mod.rs): a wire CIF
        // whose Extension Field disagrees with its attached blocks parses
        // verbatim (the core listener needs the raw field for its
        // bit-without-block ROGUE checks), but re-encoding derives the field
        // from the blocks, so the inconsistent value does not survive.
        let mut buf = CONCLUSION_REQUEST_BYTES.to_vec();
        buf[6 .. 8].copy_from_slice(&0x9320_u16.to_be_bytes()); // bogus bits
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        assert_eq!(parsed.extension_field, 0x9320); // verbatim for validation
        let reparsed = HandshakeCif::parse_cif(&encoded(&parsed)).unwrap();
        assert_ne!(reparsed, parsed); // the intentional exception
        assert_eq!(reparsed.extension_field, HS_EXT_HSREQ | HS_EXT_CONFIG);
        // Everything else survives the round trip.
        assert_eq!(
            HandshakeCif {
                extension_field: parsed.extension_field,
                ..reparsed
            },
            parsed
        );
    }

    // -- Flags -----------------------------------------------------------------

    #[test]
    fn live_default_flags() {
        let flags = HsFlags::live_defaults();
        assert_eq!(flags.0, 0x3F);
        assert!(flags.contains(HsFlags::TSBPDSND));
        assert!(flags.contains(HsFlags::TSBPDRCV));
        assert!(flags.contains(HsFlags::CRYPT));
        assert!(flags.contains(HsFlags::TLPKTDROP));
        assert!(flags.contains(HsFlags::PERIODICNAK));
        assert!(flags.contains(HsFlags::REXMITFLG));
        assert!(!flags.contains(HsFlags::STREAM));
        assert!(!flags.contains(HsFlags::PACKET_FILTER));
    }

    // -- Truncated / garbage input -----------------------------------------------

    #[test]
    fn parse_rejects_short_cif() {
        assert_eq!(HandshakeCif::parse_cif(&[]), Err(PacketError::TooShort));
        assert_eq!(
            HandshakeCif::parse_cif(&[0u8; 47]),
            Err(PacketError::TooShort)
        );
    }

    #[test]
    fn parse_ignores_trailing_stray_bytes() {
        // libsrt sizes the extension region in whole words; 1-3 stray bytes
        // after the last whole block must be ignored, not kill the CIF.
        for extra in 1 .. 4 {
            let mut buf = INDUCTION_REQUEST_BYTES.to_vec();
            buf.extend(std::iter::repeat_n(0xAA, extra));
            let parsed = HandshakeCif::parse_cif(&buf)
                .unwrap_or_else(|e| panic!("stray {extra} byte(s) must not fail parsing: {e}"));
            assert!(parsed.extensions.is_empty());
        }
        // Same after a complete extension block.
        for extra in 1 .. 4 {
            let mut buf = CONCLUSION_REQUEST_BYTES.to_vec();
            buf.extend(std::iter::repeat_n(0xAA, extra));
            let parsed = HandshakeCif::parse_cif(&buf).unwrap();
            assert_eq!(parsed.extensions, conclusion_request().extensions);
        }
    }

    #[test]
    fn parse_rejects_truncated_extension() {
        // Header claims 3 words but only 2 follow.
        let mut buf = CONCLUSION_REQUEST_BYTES.to_vec();
        buf.truncate(buf.len() - 4);
        assert_eq!(
            HandshakeCif::parse_cif(&buf),
            Err(PacketError::BadHandshake("truncated extension block"))
        );
    }

    #[test]
    fn parse_degrades_short_hsreq_to_invalid() {
        // A short HSREQ must not abort CIF parsing: the listener answers it
        // with a ROGUE rejection *after* the cookie check (the marker leaves
        // `hs_ext()` empty, which trips the core's bit-without-block check),
        // instead of silently dropping the datagram.
        let mut buf = CONCLUSION_REQUEST_BYTES[.. 48].to_vec();
        buf[6 .. 8].copy_from_slice(&HS_EXT_HSREQ.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]); // HSREQ, 2 words
        buf.extend_from_slice(&[0xAB; 8]);
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        assert_eq!(
            parsed.extensions,
            vec![HsExtension::Invalid {
                cmd: SRT_CMD_HSREQ,
                data: vec![0xAB; 8],
            }]
        );
        assert!(parsed.hs_ext().is_none());
        // The raw content is preserved and Invalid maps back to the HSREQ
        // extension-field bit: re-encoding is byte-identical.
        assert_eq!(parsed.extension_bits(), HS_EXT_HSREQ);
        assert_eq!(encoded(&parsed), buf);

        // Short HSRSP degrades the same way (caller side: fast ROGUE fail).
        let mut buf = INDUCTION_REQUEST_BYTES.to_vec();
        buf.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // HSRSP, 0 words
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        assert_eq!(
            parsed.extensions,
            vec![HsExtension::Invalid {
                cmd: SRT_CMD_HSRSP,
                data: vec![],
            }]
        );
    }

    #[test]
    fn parse_tolerates_long_hsreq() {
        // libsrt reads only the first 3 words; longer blocks must parse.
        let mut buf = INDUCTION_REQUEST_BYTES.to_vec();
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x04]); // HSREQ, 4 words
        buf.extend_from_slice(&[0x00, 0x01, 0x04, 0x04]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3F]);
        buf.extend_from_slice(&[0x00, 0x78, 0x00, 0x00]);
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // extra word
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        let fields = parsed.hs_ext().unwrap();
        assert_eq!(fields.srt_version, SRT_VERSION);
        assert_eq!(fields.recv_latency_ms, 120);
        assert_eq!(fields.send_latency_ms, 0);
    }

    #[test]
    fn parse_rejects_bad_handshake_type() {
        let mut buf = INDUCTION_REQUEST_BYTES;
        buf[20 .. 24].copy_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        assert_eq!(
            HandshakeCif::parse_cif(&buf),
            Err(PacketError::BadHandshake("unknown handshake type"))
        );
        buf[20 .. 24].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFD]); // DONE
        assert!(HandshakeCif::parse_cif(&buf).is_err());
    }

    #[test]
    fn parse_rejects_out_of_range_isn() {
        // Bit 31 set: not representable in SeqNumber.
        let mut buf = INDUCTION_REQUEST_BYTES;
        buf[8] |= 0x80;
        assert_eq!(
            HandshakeCif::parse_cif(&buf),
            Err(PacketError::BadHandshake("ISN outside valid range"))
        );

        // Exact boundary: CHandShake::valid() requires ISN < 0x7FFF_FFFF —
        // the max sequence number itself is invalid (spec handshake.md §2.1).
        let mut buf = INDUCTION_REQUEST_BYTES;
        buf[8 .. 12].copy_from_slice(&[0x7F, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            HandshakeCif::parse_cif(&buf),
            Err(PacketError::BadHandshake("ISN outside valid range"))
        );

        // One below the boundary is the largest valid ISN.
        let mut buf = INDUCTION_REQUEST_BYTES;
        buf[8 .. 12].copy_from_slice(&[0x7F, 0xFF, 0xFF, 0xFE]);
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        assert_eq!(parsed.initial_seq, SeqNumber::new(0x7FFF_FFFE));
    }

    #[test]
    fn parse_degrades_bad_sid_length_to_invalid() {
        // SID length 0 / > 512 must not abort CIF parsing: the listener
        // rejects the connection (ROGUE) after the cookie check instead of
        // silently dropping the datagram (spec handshake.md §5.3 step 6).

        // Zero-length SID.
        let mut buf = INDUCTION_REQUEST_BYTES.to_vec();
        buf.extend_from_slice(&[0x00, 0x05, 0x00, 0x00]);
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        assert_eq!(
            parsed.extensions,
            vec![HsExtension::Invalid {
                cmd: SRT_CMD_SID,
                data: vec![],
            }]
        );
        assert_eq!(parsed.stream_id(), None);

        // Over 512 bytes (129 words).
        let mut buf = INDUCTION_REQUEST_BYTES.to_vec();
        buf.extend_from_slice(&[0x00, 0x05, 0x00, 0x81]);
        buf.extend(std::iter::repeat_n(0x61, 129 * 4));
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        assert_eq!(
            parsed.extensions,
            vec![HsExtension::Invalid {
                cmd: SRT_CMD_SID,
                data: vec![0x61; 129 * 4],
            }]
        );
        assert_eq!(parsed.stream_id(), None);
    }

    #[test]
    fn parse_accepts_non_utf8_sid_lossily() {
        // libsrt 1.4.4 accepts non-UTF-8 StreamIDs (the content is an
        // arbitrary byte string); such callers must be able to connect. The
        // String-typed codec surfaces them via from_utf8_lossy (documented
        // on the StreamId variant).
        let mut buf = INDUCTION_REQUEST_BYTES.to_vec();
        buf.extend_from_slice(&[0x00, 0x05, 0x00, 0x01]);
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]); // word arrives reversed
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        let expected = String::from_utf8_lossy(&[0xFC, 0xFD, 0xFE, 0xFF]).into_owned();
        assert_eq!(parsed.stream_id(), Some(expected.as_str()));

        // Mixed content keeps the decodable part readable.
        let mut buf = INDUCTION_REQUEST_BYTES.to_vec();
        buf.extend_from_slice(&[0x00, 0x05, 0x00, 0x01]);
        buf.extend_from_slice(&[0xFF, 0x62, 0x61, 0x63]); // "cab\xFF" reversed
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        assert_eq!(parsed.stream_id(), Some("cab\u{FFFD}"));
    }

    #[test]
    fn parse_accepts_non_utf8_congestion_as_non_live() {
        // A non-UTF-8 congestion name parses lossily; it can never equal
        // "live", so the core's existing CONGESTION rejection path fires
        // (libsrt compares raw bytes with "live" — same outcome).
        let mut buf = INDUCTION_REQUEST_BYTES.to_vec();
        buf.extend_from_slice(&[0x00, 0x06, 0x00, 0x01]);
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
        let parsed = HandshakeCif::parse_cif(&buf).unwrap();
        match &parsed.extensions[0] {
            HsExtension::Congestion(name) => assert_ne!(name, "live"),
            other => panic!("expected Congestion, got {other:?}"),
        }
    }

    #[test]
    fn parse_garbage_does_not_panic() {
        // Deterministic pseudo-random garbage of assorted lengths.
        let mut state = 0x1234_5678_u32;
        for len in [0usize, 1, 15, 16, 47, 48, 49, 63, 64, 100, 200] {
            let mut buf = Vec::with_capacity(len);
            for _ in 0 .. len {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                buf.push((state >> 24) as u8);
            }
            let _ = HandshakeCif::parse_cif(&buf); // must not panic
        }
    }
}
