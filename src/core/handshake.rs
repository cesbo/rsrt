//! HSv5 caller-listener handshake state machines (sans-I/O).
//!
//! Protocol reference: docs/spec/handshake.md.
//!
//! Caller: INDUCTION (version 4, cookie 0) → listener replies (version 5,
//! `SRT_MAGIC`, cookie) → CONCLUSION (version 5, HSREQ [+ SID]) → listener
//! replies CONCLUSION/HSRSP → established. Requests are retransmitted every
//! 250 ms; the whole exchange is bounded by `SrtOptions::connect_timeout`.
//!
//! Listener: stateless until a valid CONCLUSION arrives — INDUCTION requests
//! are answered with a SYN-cookie reply that encodes (peer address, minute).
//! A valid CONCLUSION (cookie matches, ±1 minute) yields a [`Negotiated`].

use std::{
    net::SocketAddrV4,
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

use super::time::Timebase;
use crate::{
    error::SrtError,
    options::SrtOptions,
    packet::{
        reject,
        ControlPacket,
        ControlType,
        HandshakeCif,
        HandshakeType,
        HsExtFields,
        HsExtension,
        HsFlags,
        Packet,
        SeqNumber,
        SocketId,
        HS_EXT_CONFIG,
        HS_EXT_HSREQ,
        HS_EXT_KMREQ,
        SRT_CMD_FILTER,
        SRT_CMD_GROUP,
        SRT_MAGIC,
        SRT_VERSION,
    },
};

/// Interval between handshake request retransmissions.
pub const HS_RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// Handshake CIF Version values.
const HS_VERSION_UDT4: u32 = 4;
const HS_VERSION_SRT1: u32 = 5;

/// Minimum HSREQ/HSRSP SRT version for an HSv5 peer (1.3.0); below this the
/// peer is rejected as ROGUE (docs/spec/handshake.md §4.1).
const SRT_VERSION_FEAT_HSV5: u32 = 0x0001_0300;

/// Legacy UDT socket type (`UDT_DGRAM`) carried in the Extension Field of
/// the caller's INDUCTION request; unchecked by libsrt 1.4.4 but always sent.
const UDT_DGRAM: u16 = 2;

/// Everything the established connection needs from the handshake.
#[derive(Clone, Debug)]
pub struct Negotiated {
    pub remote: SocketAddrV4,
    pub local_socket_id: SocketId,
    pub peer_socket_id: SocketId,
    /// First sequence number of the data we send.
    pub send_initial_seq: SeqNumber,
    /// First sequence number of the data we receive.
    pub recv_initial_seq: SeqNumber,
    /// Effective TSBPD latency for the direction we send in.
    pub snd_latency: Duration,
    /// Effective TSBPD latency for the direction we receive in.
    pub rcv_latency: Duration,
    /// StreamID supplied by the caller, if any.
    pub streamid: Option<String>,
    /// Agreed MSS: min(ours, peer's).
    pub mss: u32,
    /// Peer's maximum flow window.
    pub flow_window: u32,
}

enum CallerState {
    /// Retransmitting the INDUCTION request, waiting for the cookie.
    Induction,
    /// Retransmitting the CONCLUSION request with the adopted cookie.
    Conclusion {
        cookie: u32,
    },
    Established,
    /// A terminal error was already surfaced through `handle_handshake`.
    Failed,
}

/// Caller-side handshake state machine.
pub struct CallerHandshake {
    remote: SocketAddrV4,
    local_socket_id: SocketId,
    initial_seq: SeqNumber,
    timebase: Timebase,
    opts: SrtOptions,
    state: CallerState,
    /// The current request is (re)sent when `now >= next_send`.
    next_send: Instant,
    /// Overall connect deadline (`opts.connect_timeout` after start).
    deadline: Instant,
}

impl CallerHandshake {
    /// Starts a handshake towards `remote`. The first INDUCTION request is
    /// queued immediately (returned by the first `poll_transmit`).
    pub fn new(
        now: Instant,
        remote: SocketAddrV4,
        local_socket_id: SocketId,
        initial_seq: SeqNumber,
        timebase: Timebase,
        opts: &SrtOptions,
    ) -> Self {
        debug!(%remote, id = ?local_socket_id, isn = %initial_seq, "caller handshake started");
        CallerHandshake {
            remote,
            local_socket_id,
            initial_seq,
            timebase,
            opts: opts.clone(),
            state: CallerState::Induction,
            next_send: now,
            deadline: now + opts.connect_timeout,
        }
    }

    /// Feeds a received handshake CIF.
    ///
    /// - `Ok(Some(_))` — handshake complete, connection established;
    /// - `Ok(None)` — keep going (a follow-up request may be queued);
    /// - `Err(_)` — handshake failed terminally (rejection, version mismatch, peer requires
    ///   encryption, ...).
    pub fn handle_handshake(
        &mut self,
        now: Instant,
        cif: &HandshakeCif,
    ) -> Result<Option<Negotiated>, SrtError> {
        if matches!(self.state, CallerState::Established | CallerState::Failed) {
            trace!("handshake packet ignored in terminal state");
            return Ok(None);
        }
        if let HandshakeType::Rejection(code) = cif.handshake_type {
            warn!(code, "connection rejected by peer");
            return self.fail(reject_error(code));
        }
        match self.state {
            CallerState::Induction => self.on_induction_response(now, cif),
            CallerState::Conclusion { .. } => self.on_conclusion_response(cif),
            CallerState::Established | CallerState::Failed => unreachable!(),
        }
    }

    /// Next packet to send (initial request or a due retransmission).
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Packet> {
        let cookie = match self.state {
            CallerState::Induction => None,
            CallerState::Conclusion { cookie } => Some(cookie),
            CallerState::Established | CallerState::Failed => return None,
        };
        if self.is_timed_out(now) || now < self.next_send {
            return None;
        }
        self.next_send = now + HS_RETRY_INTERVAL;
        // Rebuilt on every retransmission: each carries a fresh Timestamp.
        let cif = match cookie {
            None => self.induction_cif(),
            Some(cookie) => self.conclusion_cif(cookie),
        };
        trace!(hs_type = ?cif.handshake_type, "handshake request (re)transmitted");
        Some(self.packet(now, cif))
    }

    /// When `poll_transmit` should next be polled (retransmit deadline).
    pub fn next_deadline(&self) -> Option<Instant> {
        match self.state {
            CallerState::Induction | CallerState::Conclusion { .. } => {
                Some(self.next_send.min(self.deadline))
            }
            CallerState::Established | CallerState::Failed => None,
        }
    }

    /// True once the overall connect timeout has expired.
    pub fn is_timed_out(&self, now: Instant) -> bool {
        matches!(
            self.state,
            CallerState::Induction | CallerState::Conclusion { .. }
        ) && now >= self.deadline
    }

    fn fail(&mut self, err: SrtError) -> Result<Option<Negotiated>, SrtError> {
        self.state = CallerState::Failed;
        Err(err)
    }

    fn on_induction_response(
        &mut self,
        now: Instant,
        cif: &HandshakeCif,
    ) -> Result<Option<Negotiated>, SrtError> {
        if cif.handshake_type != HandshakeType::Induction {
            warn!(hs_type = ?cif.handshake_type, "unexpected handshake type during induction; ignored");
            return Ok(None);
        }
        // libsrt takes any version > 4 as HSv5-capable; 4 or below is an
        // HSv4-only listener, out of scope.
        if cif.version <= HS_VERSION_UDT4 {
            warn!(version = cif.version, "listener is not HSv5-capable");
            return self.fail(SrtError::Rejected(reject::VERSION));
        }
        if cif.extension_field != SRT_MAGIC {
            // libsrt 1.4.4 warns and continues (the draft says reject).
            warn!(
                field = cif.extension_field,
                "induction response lacks SRT magic; continuing"
            );
        }
        // The CIF socket id here is our own id echoed back — never read it;
        // the peer's id is learned from the CONCLUSION response only.
        debug!(
            cookie = cif.cookie,
            "induction response: adopting cookie, sending CONCLUSION"
        );
        self.state = CallerState::Conclusion { cookie: cif.cookie };
        self.next_send = now; // do not wait for the 250 ms tick
        Ok(None)
    }

    fn on_conclusion_response(
        &mut self,
        cif: &HandshakeCif,
    ) -> Result<Option<Negotiated>, SrtError> {
        match cif.handshake_type {
            HandshakeType::Conclusion => {}
            HandshakeType::Induction => {
                // A retransmitted induction response that crossed our
                // CONCLUSION on the wire; the cookie is already adopted.
                trace!("duplicate induction response ignored");
                return Ok(None);
            }
            other => {
                warn!(hs_type = ?other, "unexpected handshake type during conclusion; ignored");
                return Ok(None);
            }
        }
        if cif.version == 0 {
            // Version 0 in a CONCLUSION-phase handshake marks a rejection.
            warn!("conclusion response version 0: rejected by peer");
            return self.fail(SrtError::Rejected(reject::PEER));
        }
        if cif.version <= HS_VERSION_UDT4 {
            warn!(version = cif.version, "conclusion response is not HSv5");
            return self.fail(SrtError::Rejected(reject::VERSION));
        }
        if !cif_valid(cif) {
            warn!(
                mss = cif.mss,
                flow_window = cif.flow_window,
                "invalid conclusion response"
            );
            return self.fail(SrtError::Rejected(reject::ROGUE));
        }
        // Security check: the listener must adopt and echo our ISN.
        if cif.initial_seq != self.initial_seq {
            warn!(got = %cif.initial_seq, want = %self.initial_seq, "ISN echo mismatch; aborting");
            return self.fail(SrtError::Rejected(reject::ROGUE));
        }
        if cif
            .extensions
            .iter()
            .any(|e| matches!(e, HsExtension::KmReq(_) | HsExtension::KmRsp(_)))
        {
            // A non-enforced encrypted listener answers with a KMRSP error
            // block; an unencrypted endpoint must abort (spec §9 B).
            warn!("conclusion response carries key material; encryption unsupported");
            return self.fail(SrtError::EncryptionUnsupported);
        }
        // Spec §5.4 step 5: the response must carry Extension Field bit 0x1
        // and an HSRSP (type 2) block. The decoder parses blocks regardless
        // of the bits, so check the bit explicitly (libsrt rejects
        // ext_flags == 0 as ROGUE); an HSREQ block here (e.g. our own
        // request reflected back) has swapped latency semantics — ROGUE too.
        if cif.extension_field & HS_EXT_HSREQ == 0 {
            warn!(
                ext = cif.extension_field,
                "conclusion response lacks the HSREQ extension bit"
            );
            return self.fail(SrtError::Rejected(reject::ROGUE));
        }
        let hs_rsp = cif.extensions.iter().find_map(|e| match e {
            HsExtension::HsRsp(f) => Some(f),
            _ => None,
        });
        let Some(hs) = hs_rsp else {
            warn!("conclusion response without HSRSP");
            return self.fail(SrtError::Rejected(reject::ROGUE));
        };
        if hs.srt_version < SRT_VERSION_FEAT_HSV5 {
            warn!(
                srt_version = hs.srt_version,
                "peer SRT version below HSv5 feature level"
            );
            return self.fail(SrtError::Rejected(reject::ROGUE));
        }
        if hs.flags.contains(HsFlags::STREAM) {
            warn!("peer negotiated stream mode; live mode requires message API");
            return self.fail(SrtError::Rejected(reject::MESSAGEAPI));
        }
        if !hs.flags.contains(HsFlags::TSBPDSND | HsFlags::TSBPDRCV) {
            warn!(
                flags = hs.flags.0,
                "HSRSP lacks TSBPD flags; adopting latencies anyway"
            );
        }
        let negotiated = Negotiated {
            remote: self.remote,
            local_socket_id: self.local_socket_id,
            // Learned from the CONCLUSION response only (the induction
            // response echoes our own id in this field).
            peer_socket_id: cif.socket_id,
            // Both directions start from our (the caller's) ISN.
            send_initial_seq: self.initial_seq,
            recv_initial_seq: self.initial_seq,
            // HSRSP latencies are final: RcvTsbpdDelay is the peer's receive
            // latency (our send direction), SndTsbpdDelay is ours.
            snd_latency: ms_dur(hs.recv_latency_ms),
            rcv_latency: ms_dur(hs.send_latency_ms),
            streamid: self.opts.streamid.clone(),
            mss: cif.mss,
            flow_window: cif.flow_window,
        };
        debug!(
            peer = ?negotiated.peer_socket_id,
            mss = negotiated.mss,
            rcv_latency = ?negotiated.rcv_latency,
            snd_latency = ?negotiated.snd_latency,
            "handshake established (caller)"
        );
        self.state = CallerState::Established;
        Ok(Some(negotiated))
    }

    fn induction_cif(&self) -> HandshakeCif {
        HandshakeCif {
            version: HS_VERSION_UDT4, // mandatory HSv4-compat value
            encryption: 0,
            extension_field: UDT_DGRAM,
            initial_seq: self.initial_seq,
            mss: self.opts.mss,
            flow_window: self.opts.flow_window,
            handshake_type: HandshakeType::Induction,
            socket_id: self.local_socket_id,
            cookie: 0,
            peer_ip: HandshakeCif::encode_peer_ip(*self.remote.ip()),
            extensions: vec![],
        }
    }

    fn conclusion_cif(&self, cookie: u32) -> HandshakeCif {
        let mut extensions = vec![HsExtension::HsReq(HsExtFields {
            srt_version: SRT_VERSION,
            flags: HsFlags::live_defaults(),
            recv_latency_ms: ms_u16(self.opts.latency),
            send_latency_ms: ms_u16(self.opts.peer_latency),
        })];
        let mut extension_field = HS_EXT_HSREQ;
        if let Some(sid) = &self.opts.streamid {
            if !sid.is_empty() && sid.len() <= 512 {
                extensions.push(HsExtension::StreamId(sid.clone()));
                extension_field |= HS_EXT_CONFIG;
            } else {
                // The runtime layer validates length up front; never let an
                // out-of-range SID reach the wire encoder.
                warn!(
                    len = sid.len(),
                    "stream id length out of range; not attached"
                );
            }
        }
        HandshakeCif {
            version: HS_VERSION_SRT1,
            extension_field,
            handshake_type: HandshakeType::Conclusion,
            cookie, // the induction cookie, echoed verbatim (opaque to us)
            extensions,
            ..self.induction_cif()
        }
    }

    fn packet(&self, now: Instant, cif: HandshakeCif) -> Packet {
        Packet::Control(ControlPacket {
            timestamp: self.timebase.timestamp(now),
            // Both request kinds go to dst 0 ("connection request"): a
            // libsrt listener routes only dst-0 packets to connection
            // handling — a non-zero dst CONCLUSION would never connect.
            dst_socket_id: SocketId::HANDSHAKE,
            control_type: ControlType::Handshake(cif),
        })
    }
}

/// Listener-side handshake responder. Stateless per peer: everything a
/// conclusion needs to be validated is carried in the SYN cookie.
pub struct Listener {
    secret: u64,
    timebase: Timebase,
    opts: SrtOptions,
}

/// Outcome of feeding one handshake packet to the listener.
pub enum ListenerAction {
    /// Send this reply (induction response, or a rejection).
    Reply(Packet),
    /// Connection accepted: send `reply` and create the connection.
    ///
    /// `reply` must also be retransmitted by the accepted connection if the
    /// peer repeats its CONCLUSION (the response may have been lost).
    Accept {
        reply: Packet,
        negotiated: Box<Negotiated>,
    },
    /// Ignore the packet (e.g. stale cookie, rendezvous attempt).
    Drop,
}

impl Listener {
    /// `secret` seeds the SYN cookie; `timebase` stamps reply packets.
    pub fn new(secret: u64, timebase: Timebase, opts: SrtOptions) -> Self {
        Listener {
            secret,
            timebase,
            opts,
        }
    }

    /// Handles a handshake packet from an unknown peer.
    ///
    /// `new_socket_id` / `new_initial_seq` are the identifiers to assign if
    /// this packet completes a connection (the runtime provides fresh random
    /// values on every call; they are only consumed on `Accept`).
    ///
    /// Encryption requests are rejected with `reject::UNSECURE`; rendezvous
    /// (WAVEAHAND) is dropped; HSv4 conclusions are rejected with
    /// `reject::VERSION`.
    pub fn handle_handshake(
        &mut self,
        now: Instant,
        from: SocketAddrV4,
        cif: &HandshakeCif,
        new_socket_id: SocketId,
        new_initial_seq: SeqNumber,
    ) -> ListenerAction {
        // In caller-listener mode the listener never generates an ISN: it
        // adopts the caller's for both directions (echoed for the security
        // check). `new_initial_seq` is deliberately unused.
        let _ = new_initial_seq;
        match cif.handshake_type {
            HandshakeType::Induction => self.on_induction(now, from, cif),
            HandshakeType::Conclusion => self.on_conclusion(now, from, cif, new_socket_id),
            HandshakeType::Waveahand => {
                // Rendezvous is out of scope; libsrt disposes of it via the
                // failed cookie check (silent ignore).
                debug!(%from, "rendezvous WAVEAHAND dropped (unsupported)");
                ListenerAction::Drop
            }
            other => {
                trace!(%from, hs_type = ?other, "handshake type ignored by listener");
                ListenerAction::Drop
            }
        }
    }

    /// Stateless SYN cookie for `from` at minute granularity.
    pub fn cookie(&self, now: Instant, from: SocketAddrV4) -> u32 {
        self.cookie_at(self.minute(now), from)
    }

    fn on_induction(&self, now: Instant, from: SocketAddrV4, cif: &HandshakeCif) -> ListenerAction {
        // Stateless echo of the request: only Version, the type-word halves
        // and the Cookie change (spec §5.2). In particular the CIF socket id
        // stays the *caller's* id — no libsrt caller reads it.
        let mut reply = cif.clone();
        reply.version = HS_VERSION_SRT1;
        reply.encryption = 0; // no cipher advertised
        reply.extension_field = SRT_MAGIC;
        reply.cookie = self.cookie(now, from);
        reply.extensions = Vec::new();
        trace!(%from, cookie = reply.cookie, "induction request answered");
        ListenerAction::Reply(self.packet(now, cif.socket_id, reply))
    }

    fn on_conclusion(
        &self,
        now: Instant,
        from: SocketAddrV4,
        cif: &HandshakeCif,
        new_socket_id: SocketId,
    ) -> ListenerAction {
        // `valid()` runs before the cookie check (NOTES.md); both failures
        // are silent ignores — no response is sent.
        if !cif_valid(cif) {
            warn!(
                %from,
                version = cif.version,
                mss = cif.mss,
                flow_window = cif.flow_window,
                "invalid conclusion CIF dropped"
            );
            return ListenerAction::Drop;
        }
        if !self.cookie_ok(now, from, cif.cookie) {
            warn!(%from, cookie = cif.cookie, "wrong SYN cookie; conclusion dropped");
            return ListenerAction::Drop;
        }
        if cif.version != HS_VERSION_SRT1 {
            // HSv4 callers are deliberately out of scope (a real libsrt
            // listener would accept them).
            warn!(%from, version = cif.version, "unsupported conclusion version rejected");
            return self.rejection(now, cif, reject::VERSION);
        }
        // Extension Field bits must match the attached blocks (both
        // bit-without-block and block-without-bit are ROGUE); ext == 0 and a
        // missing mandatory HSREQ land here too.
        let has_hs = cif
            .extensions
            .iter()
            .any(|e| matches!(e, HsExtension::HsReq(_) | HsExtension::HsRsp(_)));
        let has_km = cif
            .extensions
            .iter()
            .any(|e| matches!(e, HsExtension::KmReq(_) | HsExtension::KmRsp(_)));
        let ext = cif.extension_field;
        if ext & HS_EXT_HSREQ == 0 || !has_hs || ((ext & HS_EXT_KMREQ != 0) != has_km) {
            warn!(%from, ext, has_hs, has_km, "extension field / block mismatch");
            return self.rejection(now, cif, reject::ROGUE);
        }
        // Unencrypted implementation with enforced-encryption semantics: a
        // peer attaching key material (KMREQ) is rejected with UNSECURE
        // (spec §9 A). The advertised-PBKEYLEN half of the type word alone
        // is ignored (§2: an unencrypted implementation ignores the received
        // Encryption Field; libsrt merely records it via
        // checkUpdateCryptoKeyLen) — pbkeylen without a passphrase is legal.
        if has_km {
            warn!(%from, encryption = cif.encryption, "peer requires encryption; rejecting");
            return self.rejection(now, cif, reject::UNSECURE);
        }
        if cif.encryption != 0 {
            debug!(%from, encryption = cif.encryption, "advertised PBKEYLEN ignored (no KMREQ)");
        }
        let hs = cif.hs_ext().expect("HSREQ presence checked above");
        if hs.srt_version < SRT_VERSION_FEAT_HSV5 {
            warn!(%from, srt_version = hs.srt_version, "peer SRT version below HSv5 feature level");
            return self.rejection(now, cif, reject::ROGUE);
        }
        if hs.flags.contains(HsFlags::STREAM) {
            warn!(%from, "stream-mode caller rejected (live mode = message API)");
            return self.rejection(now, cif, reject::MESSAGEAPI);
        }
        for block in &cif.extensions {
            match block {
                HsExtension::Congestion(name) if name != "live" => {
                    warn!(%from, name, "incompatible congestion controller");
                    return self.rejection(now, cif, reject::CONGESTION);
                }
                HsExtension::Unknown {
                    cmd: SRT_CMD_FILTER,
                    ..
                } => {
                    warn!(%from, "packet filter unsupported; rejecting");
                    return self.rejection(now, cif, reject::FILTER);
                }
                HsExtension::Unknown {
                    cmd: SRT_CMD_GROUP, ..
                } => {
                    // Non-bonding libsrt builds skip GROUP silently; so do we.
                    trace!(%from, "GROUP extension skipped");
                }
                HsExtension::Unknown { cmd, .. } => {
                    trace!(%from, cmd, "unknown handshake extension skipped");
                }
                HsExtension::Invalid { cmd, .. } => {
                    // Structurally broken block (bad SID length, short
                    // HSREQ...): libsrt answers with ROGUE, not silence.
                    warn!(%from, cmd, "malformed handshake extension; rejecting");
                    return self.rejection(now, cif, reject::ROGUE);
                }
                _ => {}
            }
        }
        // Latency negotiation (§4.2): each direction is the max of the
        // receiver's own setting and the sender's proposal.
        let rcv_latency = self.opts.latency.max(ms_dur(hs.send_latency_ms));
        let snd_latency = self.opts.peer_latency.max(ms_dur(hs.recv_latency_ms));
        let mss = self.opts.mss.min(cif.mss);
        let negotiated = Negotiated {
            remote: from,
            local_socket_id: new_socket_id,
            peer_socket_id: cif.socket_id,
            // Adopt the caller's ISN for both directions.
            send_initial_seq: cif.initial_seq,
            recv_initial_seq: cif.initial_seq,
            snd_latency,
            rcv_latency,
            streamid: cif.stream_id().map(str::to_owned),
            mss,
            flow_window: cif.flow_window,
        };
        let reply_cif = HandshakeCif {
            version: HS_VERSION_SRT1,
            encryption: 0,
            extension_field: HS_EXT_HSREQ,
            initial_seq: cif.initial_seq, // echoed: the caller aborts on mismatch
            mss,
            flow_window: self.opts.flow_window,
            handshake_type: HandshakeType::Conclusion,
            socket_id: new_socket_id, // becomes the caller's peer id
            cookie: cif.cookie,       // echoed like libsrt; callers ignore it
            peer_ip: HandshakeCif::encode_peer_ip(*from.ip()),
            extensions: vec![HsExtension::HsRsp(HsExtFields {
                srt_version: SRT_VERSION,
                flags: HsFlags::live_defaults(),
                recv_latency_ms: ms_u16(rcv_latency),
                send_latency_ms: ms_u16(snd_latency),
            })],
        };
        debug!(
            %from,
            peer = ?cif.socket_id,
            local = ?new_socket_id,
            ?rcv_latency,
            ?snd_latency,
            mss,
            "conclusion accepted"
        );
        ListenerAction::Accept {
            reply: self.packet(now, cif.socket_id, reply_cif),
            negotiated: Box::new(negotiated),
        }
    }

    /// Rejection response: the received CIF echoed with only the Handshake
    /// Type replaced and extensions stripped (spec §3.1), addressed to the
    /// caller's socket id.
    fn rejection(&self, now: Instant, cif: &HandshakeCif, code: u32) -> ListenerAction {
        let mut reply = cif.clone();
        reply.handshake_type = HandshakeType::Rejection(code);
        reply.extensions = Vec::new();
        ListenerAction::Reply(self.packet(now, cif.socket_id, reply))
    }

    fn cookie_ok(&self, now: Instant, from: SocketAddrV4, cookie: u32) -> bool {
        let minute = self.minute(now);
        cookie == self.cookie_at(minute, from)
            // Accept the previous minute too: fixes libsrt 1.4.4's
            // minute-rollover dead window (listener-local, interop-neutral).
            || (minute > 0 && cookie == self.cookie_at(minute - 1, from))
    }

    /// Minutes since the listener started (the cookie's time component).
    fn minute(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.timebase.start())
            .as_secs()
            / 60
    }

    fn cookie_at(&self, minute: u64, from: SocketAddrV4) -> u32 {
        // Any stateless-verifiable function of (ip, port, minute, secret)
        // works: the cookie is generated and checked only by this listener
        // and echoed opaquely by the caller (libsrt uses an MD5 prefix).
        // DefaultHasher (SipHash) is deterministic within a process; the
        // per-listener `secret` keys it.
        use std::hash::{
            Hash,
            Hasher,
        };
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.secret.hash(&mut hasher);
        from.ip().octets().hash(&mut hasher);
        from.port().hash(&mut hasher);
        minute.hash(&mut hasher);
        let digest = hasher.finish();
        (digest ^ (digest >> 32)) as u32
    }

    fn packet(&self, now: Instant, dst: SocketId, cif: HandshakeCif) -> Packet {
        Packet::Control(ControlPacket {
            timestamp: self.timebase.timestamp(now),
            dst_socket_id: dst,
            control_type: ControlType::Handshake(cif),
        })
    }
}

/// `CHandShake::valid()`: version ≥ 4, MSS ≥ 32, flow window ≥ 2. (The ISN
/// range check happens in the CIF parser; a `SeqNumber` is always valid.)
fn cif_valid(cif: &HandshakeCif) -> bool {
    cif.version >= HS_VERSION_UDT4 && cif.mss >= 32 && cif.flow_window >= 2
}

/// Maps a wire rejection code to the public error.
fn reject_error(code: u32) -> SrtError {
    if code == reject::UNSECURE {
        SrtError::EncryptionUnsupported
    } else {
        SrtError::Rejected(code)
    }
}

fn ms_u16(d: Duration) -> u16 {
    d.as_millis().min(u128::from(u16::MAX)) as u16
}

fn ms_dur(ms: u16) -> Duration {
    Duration::from_millis(u64::from(ms))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::packet::Timestamp;

    const CALLER_ID: SocketId = SocketId(0x0102_0304);
    const ACCEPT_ID: SocketId = SocketId(0x00A1_B2C3);
    const CALLER_ISN: SeqNumber = SeqNumber::new(0x1234_5678);
    /// Never used by design: the listener adopts the caller's ISN.
    const UNUSED_ISN: SeqNumber = SeqNumber::new(42);
    const SECRET: u64 = 0xDEAD_BEEF_F00D;

    fn caller_addr() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 50_000)
    }

    fn listener_addr() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 4200)
    }

    fn hs_cif(pkt: &Packet) -> &HandshakeCif {
        match pkt {
            Packet::Control(ControlPacket {
                control_type: ControlType::Handshake(cif),
                ..
            }) => cif,
            other => panic!("expected handshake packet, got {other:?}"),
        }
    }

    fn caller(now: Instant, opts: &SrtOptions) -> CallerHandshake {
        CallerHandshake::new(
            now,
            listener_addr(),
            CALLER_ID,
            CALLER_ISN,
            Timebase::new(now),
            opts,
        )
    }

    fn listener(now: Instant, opts: SrtOptions) -> Listener {
        Listener::new(SECRET, Timebase::new(now), opts)
    }

    fn reply_of(action: ListenerAction) -> Packet {
        match action {
            ListenerAction::Reply(p) => p,
            ListenerAction::Accept { .. } => panic!("expected Reply, got Accept"),
            ListenerAction::Drop => panic!("expected Reply, got Drop"),
        }
    }

    fn rejection_code(action: ListenerAction) -> u32 {
        let pkt = reply_of(action);
        match hs_cif(&pkt).handshake_type {
            HandshakeType::Rejection(code) => code,
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    /// Runs the full caller<->listener exchange, asserting the wire-visible
    /// invariants along the way, and returns both `Negotiated`.
    fn run_exchange(
        caller_opts: SrtOptions,
        listener_opts: SrtOptions,
    ) -> (Negotiated, Negotiated) {
        let t0 = Instant::now();
        let mut c = caller(t0, &caller_opts);
        let mut l = listener(t0, listener_opts);

        // -- INDUCTION request --
        let ind_req = c.poll_transmit(t0).expect("induction request queued");
        assert_eq!(ind_req.dst_socket_id(), SocketId::HANDSHAKE);
        let req = hs_cif(&ind_req);
        assert_eq!(req.version, 4);
        assert_eq!(req.encryption, 0);
        assert_eq!(req.extension_field, 2);
        assert_eq!(req.handshake_type, HandshakeType::Induction);
        assert_eq!(req.cookie, 0);
        assert_eq!(req.socket_id, CALLER_ID);
        assert_eq!(req.initial_seq, CALLER_ISN);
        assert_eq!(
            req.peer_ip,
            HandshakeCif::encode_peer_ip(*listener_addr().ip())
        );
        assert!(req.extensions.is_empty());

        // -- INDUCTION response --
        let action = l.handle_handshake(t0, caller_addr(), req, ACCEPT_ID, UNUSED_ISN);
        let ind_rsp = reply_of(action);
        assert_eq!(ind_rsp.dst_socket_id(), CALLER_ID);
        let rsp = hs_cif(&ind_rsp);
        assert_eq!(rsp.version, 5);
        assert_eq!(rsp.extension_field, SRT_MAGIC);
        assert_ne!(rsp.cookie, 0);
        assert_eq!(rsp.handshake_type, HandshakeType::Induction);
        // Everything else echoed verbatim — including the caller's own
        // socket id (which the caller must never read).
        assert_eq!(rsp.socket_id, CALLER_ID);
        assert_eq!(rsp.initial_seq, CALLER_ISN);
        assert_eq!(rsp.mss, caller_opts.mss);
        let cookie = rsp.cookie;

        assert!(c.handle_handshake(t0, rsp).expect("induction ok").is_none());

        // -- CONCLUSION request (sent immediately, not on the 250 ms tick) --
        let conc_req = c.poll_transmit(t0).expect("conclusion follows immediately");
        assert_eq!(conc_req.dst_socket_id(), SocketId::HANDSHAKE);
        let req = hs_cif(&conc_req);
        assert_eq!(req.version, 5);
        assert_eq!(req.encryption, 0);
        assert_eq!(req.handshake_type, HandshakeType::Conclusion);
        assert_eq!(req.cookie, cookie); // echoed verbatim
        assert_eq!(req.socket_id, CALLER_ID);
        assert_eq!(req.initial_seq, CALLER_ISN);
        let expect_ext = if caller_opts.streamid.is_some() {
            HS_EXT_HSREQ | HS_EXT_CONFIG
        } else {
            HS_EXT_HSREQ
        };
        assert_eq!(req.extension_field, expect_ext);
        let hsreq = req.hs_ext().expect("HSREQ attached");
        assert_eq!(hsreq.srt_version, SRT_VERSION);
        assert_eq!(hsreq.flags, HsFlags::live_defaults());
        assert_eq!(hsreq.recv_latency_ms, ms_u16(caller_opts.latency));
        assert_eq!(hsreq.send_latency_ms, ms_u16(caller_opts.peer_latency));
        assert_eq!(req.stream_id(), caller_opts.streamid.as_deref());

        // -- CONCLUSION response / accept --
        let action = l.handle_handshake(t0, caller_addr(), req, ACCEPT_ID, UNUSED_ISN);
        let (conc_rsp, l_neg) = match action {
            ListenerAction::Accept { reply, negotiated } => (reply, *negotiated),
            _ => panic!("expected Accept"),
        };
        assert_eq!(conc_rsp.dst_socket_id(), CALLER_ID);
        let rsp = hs_cif(&conc_rsp);
        assert_eq!(rsp.version, 5);
        assert_eq!(rsp.handshake_type, HandshakeType::Conclusion);
        assert_eq!(rsp.initial_seq, CALLER_ISN); // adopted + echoed
        assert_eq!(rsp.socket_id, ACCEPT_ID);
        assert_eq!(rsp.extension_field, HS_EXT_HSREQ);
        assert_eq!(
            rsp.peer_ip,
            HandshakeCif::encode_peer_ip(*caller_addr().ip())
        );
        assert!(rsp.stream_id().is_none()); // listener never sends SID back

        let c_neg = c
            .handle_handshake(t0, rsp)
            .expect("conclusion ok")
            .expect("established");

        // -- terminal caller state --
        assert!(c.poll_transmit(t0 + Duration::from_secs(1)).is_none());
        assert_eq!(c.next_deadline(), None);
        assert!(!c.is_timed_out(t0 + Duration::from_secs(60)));
        assert!(c
            .handle_handshake(t0, rsp)
            .expect("ignored after establishment")
            .is_none());

        // -- Negotiated cross-checks --
        assert_eq!(c_neg.local_socket_id, CALLER_ID);
        assert_eq!(c_neg.peer_socket_id, ACCEPT_ID);
        assert_eq!(l_neg.local_socket_id, ACCEPT_ID);
        assert_eq!(l_neg.peer_socket_id, CALLER_ID);
        for neg in [&c_neg, &l_neg] {
            assert_eq!(neg.send_initial_seq, CALLER_ISN);
            assert_eq!(neg.recv_initial_seq, CALLER_ISN);
        }
        assert_eq!(c_neg.snd_latency, l_neg.rcv_latency);
        assert_eq!(c_neg.rcv_latency, l_neg.snd_latency);
        assert_eq!(c_neg.mss, l_neg.mss);
        assert_eq!(c_neg.remote, listener_addr());
        assert_eq!(l_neg.remote, caller_addr());
        (c_neg, l_neg)
    }

    // -- full exchange / negotiation ---------------------------------------

    #[test]
    fn full_exchange_defaults() {
        let (c_neg, l_neg) = run_exchange(SrtOptions::default(), SrtOptions::default());
        // Both directions land on the 120 ms default.
        assert_eq!(c_neg.rcv_latency, Duration::from_millis(120));
        assert_eq!(c_neg.snd_latency, Duration::from_millis(120));
        assert_eq!(l_neg.rcv_latency, Duration::from_millis(120));
        assert_eq!(l_neg.snd_latency, Duration::from_millis(120));
        assert_eq!(c_neg.mss, 1500);
        assert_eq!(c_neg.flow_window, 8192);
        assert_eq!(l_neg.flow_window, 8192);
        assert_eq!(c_neg.streamid, None);
        assert_eq!(l_neg.streamid, None);
    }

    #[test]
    fn latency_caller_higher() {
        let copts = SrtOptions::default().latency(Duration::from_millis(250));
        let (c_neg, l_neg) = run_exchange(copts, SrtOptions::default());
        // Caller receives at 250 (its own ask), listener at its default 120.
        assert_eq!(c_neg.rcv_latency, Duration::from_millis(250));
        assert_eq!(c_neg.snd_latency, Duration::from_millis(120));
        assert_eq!(l_neg.rcv_latency, Duration::from_millis(120));
        assert_eq!(l_neg.snd_latency, Duration::from_millis(250));
    }

    #[test]
    fn latency_listener_higher() {
        let lopts = SrtOptions::default().latency(Duration::from_millis(300));
        let (c_neg, l_neg) = run_exchange(SrtOptions::default(), lopts);
        // Listener receives at 300 = max(300, caller's peer proposal 0).
        assert_eq!(l_neg.rcv_latency, Duration::from_millis(300));
        assert_eq!(c_neg.snd_latency, Duration::from_millis(300));
        assert_eq!(c_neg.rcv_latency, Duration::from_millis(120));
        assert_eq!(l_neg.snd_latency, Duration::from_millis(120));
    }

    #[test]
    fn latency_peer_proposals_win_by_max() {
        // Caller proposes 500 for the direction it sends in; listener
        // proposes 400 for the direction it sends in. max() beats both
        // receivers' smaller own settings.
        let copts = SrtOptions::default().peer_latency(Duration::from_millis(500));
        let lopts = SrtOptions::default().peer_latency(Duration::from_millis(400));
        let (c_neg, l_neg) = run_exchange(copts, lopts);
        assert_eq!(l_neg.rcv_latency, Duration::from_millis(500)); // max(120, 500)
        assert_eq!(c_neg.snd_latency, Duration::from_millis(500));
        assert_eq!(c_neg.rcv_latency, Duration::from_millis(400)); // max(120, 400)
        assert_eq!(l_neg.snd_latency, Duration::from_millis(400));
    }

    #[test]
    fn mss_negotiated_to_min() {
        let copts = SrtOptions {
            mss: 1400,
            ..SrtOptions::default()
        };
        let lopts = SrtOptions {
            mss: 1300,
            ..SrtOptions::default()
        };
        let (c_neg, l_neg) = run_exchange(copts, lopts);
        assert_eq!(c_neg.mss, 1300);
        assert_eq!(l_neg.mss, 1300);

        let copts = SrtOptions {
            mss: 1200,
            ..SrtOptions::default()
        };
        let (c_neg, _) = run_exchange(copts, SrtOptions::default());
        assert_eq!(c_neg.mss, 1200);
    }

    #[test]
    fn streamid_propagates_to_both_sides() {
        let copts = SrtOptions::default().streamid("live/stream-01");
        let (c_neg, l_neg) = run_exchange(copts, SrtOptions::default());
        assert_eq!(c_neg.streamid.as_deref(), Some("live/stream-01"));
        assert_eq!(l_neg.streamid.as_deref(), Some("live/stream-01"));
    }

    #[test]
    fn repeated_conclusion_is_reaccepted() {
        // The stateless listener answers every valid CONCLUSION; the runtime
        // dedupes by (addr, socket id). Same inputs → same negotiation.
        let t0 = Instant::now();
        let l = listener(t0, SrtOptions::default());
        let cif = valid_conclusion(&l, t0);
        let mut negs = vec![];
        for _ in 0 .. 2 {
            let mut l2 = listener(t0, SrtOptions::default());
            match l2.handle_handshake(t0, caller_addr(), &cif, ACCEPT_ID, UNUSED_ISN) {
                ListenerAction::Accept { reply, negotiated } => {
                    assert_eq!(hs_cif(&reply).initial_seq, CALLER_ISN);
                    negs.push(*negotiated);
                }
                _ => panic!("expected Accept"),
            }
        }
        assert_eq!(negs[0].peer_socket_id, negs[1].peer_socket_id);
        assert_eq!(negs[0].send_initial_seq, negs[1].send_initial_seq);
    }

    // -- caller timers -------------------------------------------------------

    #[test]
    fn induction_retransmits_every_250ms() {
        let t0 = Instant::now();
        let mut c = caller(t0, &SrtOptions::default());
        let first = c.poll_transmit(t0).expect("initial send");
        assert_eq!(first.timestamp(), Timestamp(0));
        // Not due again until the full interval elapses.
        assert!(c.poll_transmit(t0).is_none());
        assert!(c.poll_transmit(t0 + Duration::from_millis(249)).is_none());
        assert_eq!(c.next_deadline(), Some(t0 + HS_RETRY_INTERVAL));
        let second = c.poll_transmit(t0 + HS_RETRY_INTERVAL).expect("retransmit");
        assert_eq!(hs_cif(&second).handshake_type, HandshakeType::Induction);
        // Same request, fresh timestamp.
        assert_eq!(hs_cif(&second), hs_cif(&first));
        assert_eq!(second.timestamp(), Timestamp(250_000));
    }

    #[test]
    fn conclusion_sent_immediately_then_retransmitted() {
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        // Transition happened at t1 = t0 + 100 ms; conclusion due at once.
        let t1 = t0 + Duration::from_millis(100);
        let first = c.poll_transmit(t1).expect("conclusion immediately");
        assert_eq!(hs_cif(&first).handshake_type, HandshakeType::Conclusion);
        assert!(c.poll_transmit(t1 + Duration::from_millis(200)).is_none());
        let second = c
            .poll_transmit(t1 + HS_RETRY_INTERVAL)
            .expect("conclusion retransmit");
        assert_eq!(hs_cif(&second), hs_cif(&first));
        assert!(second.timestamp().0 > first.timestamp().0);
    }

    #[test]
    fn connect_timeout_expires() {
        let t0 = Instant::now();
        let mut c = caller(t0, &SrtOptions::default());
        assert!(!c.is_timed_out(t0));
        assert!(!c.is_timed_out(t0 + Duration::from_millis(2_999)));
        assert!(c.is_timed_out(t0 + Duration::from_secs(3)));
        // No further transmissions once the budget is exhausted.
        assert!(c.poll_transmit(t0 + Duration::from_secs(3)).is_none());
    }

    #[test]
    fn connect_timeout_is_configurable() {
        let t0 = Instant::now();
        let opts = SrtOptions::default().connect_timeout(Duration::from_millis(500));
        let mut c = caller(t0, &opts);
        assert!(c.poll_transmit(t0).is_some());
        assert!(!c.is_timed_out(t0 + Duration::from_millis(499)));
        assert!(c.is_timed_out(t0 + Duration::from_millis(500)));
    }

    #[test]
    fn next_deadline_caps_at_connect_deadline() {
        let t0 = Instant::now();
        let opts = SrtOptions::default().connect_timeout(Duration::from_millis(100));
        let mut c = caller(t0, &opts);
        assert!(c.poll_transmit(t0).is_some());
        // Retransmit would be due at t0+250 ms, but the connect deadline is
        // sooner and must drive the runtime wakeup.
        assert_eq!(c.next_deadline(), Some(t0 + Duration::from_millis(100)));
    }

    // -- caller rejection / failure paths -------------------------------------

    /// Puts a caller into the Conclusion state via a synthetic induction
    /// response (cookie 0x5EED_C00C), transitioning at t0 + 100 ms.
    fn caller_in_conclusion(t0: Instant) -> (CallerHandshake, u32) {
        let cookie = 0x5EED_C00C;
        let mut c = caller(t0, &SrtOptions::default());
        let _ = c.poll_transmit(t0).expect("induction");
        let rsp = HandshakeCif {
            version: 5,
            encryption: 0,
            extension_field: SRT_MAGIC,
            initial_seq: CALLER_ISN,
            mss: 1500,
            flow_window: 8192,
            handshake_type: HandshakeType::Induction,
            socket_id: CALLER_ID, // our own id echoed back — must not be read
            cookie,
            peer_ip: HandshakeCif::encode_peer_ip(*listener_addr().ip()),
            extensions: vec![],
        };
        let t1 = t0 + Duration::from_millis(100);
        assert!(c
            .handle_handshake(t1, &rsp)
            .expect("induction ok")
            .is_none());
        (c, cookie)
    }

    /// A well-formed CONCLUSION response for `caller_in_conclusion`.
    fn conclusion_response() -> HandshakeCif {
        HandshakeCif {
            version: 5,
            encryption: 0,
            extension_field: HS_EXT_HSREQ,
            initial_seq: CALLER_ISN,
            mss: 1500,
            flow_window: 8192,
            handshake_type: HandshakeType::Conclusion,
            socket_id: ACCEPT_ID,
            cookie: 0x5EED_C00C,
            peer_ip: HandshakeCif::encode_peer_ip(*caller_addr().ip()),
            extensions: vec![HsExtension::HsRsp(HsExtFields {
                srt_version: SRT_VERSION,
                flags: HsFlags::live_defaults(),
                recv_latency_ms: 120,
                send_latency_ms: 120,
            })],
        }
    }

    #[test]
    fn caller_maps_rejection_codes() {
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        let rsp = HandshakeCif {
            handshake_type: HandshakeType::Rejection(reject::ROGUE),
            extensions: vec![],
            ..conclusion_response()
        };
        match c.handle_handshake(t0, &rsp) {
            Err(SrtError::Rejected(code)) => assert_eq!(code, reject::ROGUE),
            other => panic!("expected Rejected(1004), got {other:?}"),
        }
        // Terminal: nothing more is sent, later packets are ignored.
        assert!(c.poll_transmit(t0 + Duration::from_secs(1)).is_none());
        assert_eq!(c.next_deadline(), None);
        assert!(c
            .handle_handshake(t0, &conclusion_response())
            .expect("ignored after failure")
            .is_none());
    }

    #[test]
    fn caller_maps_unsecure_to_encryption_unsupported() {
        // Direction B of spec §9: listener demands crypto → wire code 1011.
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        let rsp = HandshakeCif {
            handshake_type: HandshakeType::Rejection(reject::UNSECURE),
            extensions: vec![],
            ..conclusion_response()
        };
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::EncryptionUnsupported)
        ));
    }

    #[test]
    fn caller_rejection_during_induction() {
        let t0 = Instant::now();
        let mut c = caller(t0, &SrtOptions::default());
        let _ = c.poll_transmit(t0);
        let rsp = HandshakeCif {
            handshake_type: HandshakeType::Rejection(reject::BACKLOG),
            ..conclusion_response()
        };
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::Rejected(code)) if code == reject::BACKLOG
        ));
    }

    #[test]
    fn caller_aborts_on_isn_echo_mismatch() {
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        let rsp = HandshakeCif {
            initial_seq: CALLER_ISN.add(1),
            ..conclusion_response()
        };
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::Rejected(code)) if code == reject::ROGUE
        ));
        assert!(c.poll_transmit(t0 + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn caller_aborts_on_km_in_response() {
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        let mut rsp = conclusion_response();
        rsp.extensions.push(HsExtension::KmRsp(vec![0, 0, 0, 3]));
        rsp.extension_field = HS_EXT_HSREQ | HS_EXT_KMREQ;
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::EncryptionUnsupported)
        ));
    }

    #[test]
    fn caller_aborts_on_version_zero_conclusion() {
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        let rsp = HandshakeCif {
            version: 0,
            ..conclusion_response()
        };
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::Rejected(code)) if code == reject::PEER
        ));
    }

    #[test]
    fn caller_aborts_on_missing_hsrsp() {
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        let rsp = HandshakeCif {
            extensions: vec![],
            extension_field: 0,
            ..conclusion_response()
        };
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::Rejected(code)) if code == reject::ROGUE
        ));
    }

    #[test]
    fn caller_rejects_hsreq_block_as_conclusion_response() {
        // Spec §5.4 step 5: the response must carry an HSRSP (type 2) block.
        // A peer reflecting our own CONCLUSION request (HSREQ block, swapped
        // latency semantics) must be rejected as ROGUE, not established.
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        let rsp = HandshakeCif {
            extensions: vec![HsExtension::HsReq(HsExtFields {
                srt_version: SRT_VERSION,
                flags: HsFlags::live_defaults(),
                recv_latency_ms: 120,
                send_latency_ms: 0,
            })],
            ..conclusion_response()
        };
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::Rejected(code)) if code == reject::ROGUE
        ));
        assert!(c.poll_transmit(t0 + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn caller_rejects_hsrsp_without_extension_bit() {
        // Spec §5.4 step 5: Extension Field bit 0x1 must be set. The decoder
        // parses blocks regardless of the bits, so an HSRSP block attached
        // to ext == 0 must still be rejected (libsrt: ext_flags==0 → ROGUE).
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        let rsp = HandshakeCif {
            extension_field: 0,
            ..conclusion_response()
        };
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::Rejected(code)) if code == reject::ROGUE
        ));
    }

    #[test]
    fn caller_rejects_hsv4_induction_response() {
        // An HSv4 listener echoes version 4 — out of scope, abort.
        let t0 = Instant::now();
        let mut c = caller(t0, &SrtOptions::default());
        let _ = c.poll_transmit(t0);
        let rsp = HandshakeCif {
            version: 4,
            extension_field: 2,
            handshake_type: HandshakeType::Induction,
            ..conclusion_response()
        };
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::Rejected(code)) if code == reject::VERSION
        ));
    }

    #[test]
    fn caller_tolerates_missing_magic() {
        // libsrt 1.4.4 warns and continues when the magic is absent.
        let t0 = Instant::now();
        let mut c = caller(t0, &SrtOptions::default());
        let _ = c.poll_transmit(t0);
        let rsp = HandshakeCif {
            version: 5,
            extension_field: 2, // echoed request value instead of 0x4A17
            handshake_type: HandshakeType::Induction,
            cookie: 0x0C00_C1E5,
            ..conclusion_response()
        };
        assert!(c.handle_handshake(t0, &rsp).expect("continue").is_none());
        let conc = c.poll_transmit(t0).expect("conclusion proceeds");
        assert_eq!(hs_cif(&conc).handshake_type, HandshakeType::Conclusion);
        assert_eq!(hs_cif(&conc).cookie, 0x0C00_C1E5);
    }

    #[test]
    fn caller_ignores_stray_types() {
        let t0 = Instant::now();
        let mut c = caller(t0, &SrtOptions::default());
        let _ = c.poll_transmit(t0);
        // A stray CONCLUSION while still waiting for induction: ignored.
        assert!(c
            .handle_handshake(t0, &conclusion_response())
            .expect("ignored")
            .is_none());
        let (mut c, _) = caller_in_conclusion(t0);
        // A duplicate induction response while in conclusion: ignored.
        let dup = HandshakeCif {
            version: 5,
            extension_field: SRT_MAGIC,
            handshake_type: HandshakeType::Induction,
            ..conclusion_response()
        };
        assert!(c.handle_handshake(t0, &dup).expect("ignored").is_none());
        // Rendezvous WAVEAHAND: ignored.
        let wave = HandshakeCif {
            handshake_type: HandshakeType::Waveahand,
            ..conclusion_response()
        };
        assert!(c.handle_handshake(t0, &wave).expect("ignored").is_none());
    }

    // -- listener paths --------------------------------------------------------

    /// A well-formed CONCLUSION request carrying `l`'s current cookie.
    fn valid_conclusion(l: &Listener, now: Instant) -> HandshakeCif {
        HandshakeCif {
            version: 5,
            encryption: 0,
            extension_field: HS_EXT_HSREQ,
            initial_seq: CALLER_ISN,
            mss: 1500,
            flow_window: 8192,
            handshake_type: HandshakeType::Conclusion,
            socket_id: CALLER_ID,
            cookie: l.cookie(now, caller_addr()),
            peer_ip: HandshakeCif::encode_peer_ip(*listener_addr().ip()),
            extensions: vec![HsExtension::HsReq(HsExtFields {
                srt_version: SRT_VERSION,
                flags: HsFlags::live_defaults(),
                recv_latency_ms: 120,
                send_latency_ms: 0,
            })],
        }
    }

    fn handle(l: &mut Listener, now: Instant, cif: &HandshakeCif) -> ListenerAction {
        l.handle_handshake(now, caller_addr(), cif, ACCEPT_ID, UNUSED_ISN)
    }

    #[test]
    fn listener_induction_reply_echoes_request() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut req = valid_conclusion(&l, t0);
        req.handshake_type = HandshakeType::Induction;
        req.version = 4;
        req.extension_field = 2;
        req.cookie = 0;
        req.mss = 1400;
        req.flow_window = 4096;
        req.extensions = vec![];
        let reply = reply_of(handle(&mut l, t0, &req));
        assert_eq!(reply.dst_socket_id(), CALLER_ID);
        let cif = hs_cif(&reply);
        assert_eq!(cif.version, 5);
        assert_eq!(cif.extension_field, SRT_MAGIC);
        assert_eq!(cif.cookie, l.cookie(t0, caller_addr()));
        // Everything else verbatim.
        assert_eq!(cif.handshake_type, HandshakeType::Induction);
        assert_eq!(cif.socket_id, CALLER_ID);
        assert_eq!(cif.initial_seq, CALLER_ISN);
        assert_eq!(cif.mss, 1400);
        assert_eq!(cif.flow_window, 4096);
        assert_eq!(cif.peer_ip, req.peer_ip);
    }

    #[test]
    fn listener_rejects_km_extension_as_unsecure() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut cif = valid_conclusion(&l, t0);
        cif.extensions.push(HsExtension::KmReq(vec![0; 16]));
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_KMREQ;
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::UNSECURE);
    }

    #[test]
    fn listener_ignores_advertised_pbkeylen() {
        // A caller with pbkeylen set but no passphrase advertises a cipher
        // in the Encryption Field yet attaches no KMREQ. Spec §2: an
        // unencrypted implementation ignores the received value; §9 keys
        // UNSECURE on KMREQ presence only (libsrt 1.4.4 accepts this and
        // streams unencrypted).
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut cif = valid_conclusion(&l, t0);
        cif.encryption = 2; // AES-128 advertised, no KM block attached
        match handle(&mut l, t0, &cif) {
            ListenerAction::Accept { reply, .. } => {
                let rcif = hs_cif(&reply);
                assert_eq!(rcif.handshake_type, HandshakeType::Conclusion);
                assert_eq!(rcif.encryption, 0); // we never advertise a cipher
            }
            other => panic!(
                "expected Accept, got {}",
                match other {
                    ListenerAction::Reply(_) => "Reply",
                    ListenerAction::Drop => "Drop",
                    ListenerAction::Accept { .. } => unreachable!(),
                }
            ),
        }
    }

    #[test]
    fn listener_rejects_hsv4_conclusion() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut cif = valid_conclusion(&l, t0);
        cif.version = 4;
        cif.extension_field = 2; // HSv4 carries the UDT socket type here
        cif.extensions = vec![];
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::VERSION);
    }

    #[test]
    fn listener_rejection_reply_shape() {
        // Received CIF echoed, only the type replaced, extensions stripped.
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut cif = valid_conclusion(&l, t0);
        cif.extensions.push(HsExtension::KmReq(vec![0; 16]));
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_KMREQ;
        let reply = reply_of(handle(&mut l, t0, &cif));
        assert_eq!(reply.dst_socket_id(), CALLER_ID);
        let rcif = hs_cif(&reply);
        assert_eq!(
            rcif.handshake_type,
            HandshakeType::Rejection(reject::UNSECURE)
        );
        assert!(rcif.extensions.is_empty());
        assert_eq!(rcif.initial_seq, cif.initial_seq);
        assert_eq!(rcif.socket_id, cif.socket_id);
        assert_eq!(rcif.cookie, cif.cookie);
    }

    #[test]
    fn listener_drops_waveahand() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut cif = valid_conclusion(&l, t0);
        cif.handshake_type = HandshakeType::Waveahand;
        assert!(matches!(handle(&mut l, t0, &cif), ListenerAction::Drop));
        // AGREEMENT likewise never creates state.
        cif.handshake_type = HandshakeType::Agreement;
        assert!(matches!(handle(&mut l, t0, &cif), ListenerAction::Drop));
    }

    #[test]
    fn listener_drops_bad_cookie_silently() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut cif = valid_conclusion(&l, t0);
        cif.cookie = cif.cookie.wrapping_add(1);
        assert!(matches!(handle(&mut l, t0, &cif), ListenerAction::Drop));
    }

    #[test]
    fn listener_drops_invalid_cif_before_cookie_check() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        // All carry a VALID cookie: `valid()` runs first and drops silently.
        let mut cif = valid_conclusion(&l, t0);
        cif.mss = 31;
        assert!(matches!(handle(&mut l, t0, &cif), ListenerAction::Drop));
        let mut cif = valid_conclusion(&l, t0);
        cif.flow_window = 1;
        assert!(matches!(handle(&mut l, t0, &cif), ListenerAction::Drop));
        let mut cif = valid_conclusion(&l, t0);
        cif.version = 0; // fails valid(): dropped, not answered with VERSION
        assert!(matches!(handle(&mut l, t0, &cif), ListenerAction::Drop));
    }

    #[test]
    fn listener_rejects_ext_field_block_mismatch() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());

        // HSREQ bit set, no block.
        let mut cif = valid_conclusion(&l, t0);
        cif.extensions = vec![];
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::ROGUE);

        // ext == 0 with a block attached.
        let mut cif = valid_conclusion(&l, t0);
        cif.extension_field = 0;
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::ROGUE);

        // KMREQ bit without a KM block.
        let mut cif = valid_conclusion(&l, t0);
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_KMREQ;
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::ROGUE);

        // KM block without the KMREQ bit.
        let mut cif = valid_conclusion(&l, t0);
        cif.extensions.push(HsExtension::KmReq(vec![0; 16]));
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::ROGUE);
    }

    #[test]
    fn listener_rejects_stream_mode() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut cif = valid_conclusion(&l, t0);
        cif.extensions = vec![HsExtension::HsReq(HsExtFields {
            srt_version: SRT_VERSION,
            flags: HsFlags(HsFlags::live_defaults().0 | HsFlags::STREAM),
            recv_latency_ms: 120,
            send_latency_ms: 0,
        })];
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::MESSAGEAPI);
    }

    #[test]
    fn listener_rejects_malformed_extension_block() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut cif = valid_conclusion(&l, t0);
        // A structurally broken block (e.g. over-long SID) degrades to
        // HsExtension::Invalid at parse time; libsrt answers ROGUE.
        cif.extensions.push(HsExtension::Invalid {
            cmd: crate::packet::SRT_CMD_SID,
            data: vec![0; 4],
        });
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::ROGUE);
    }

    #[test]
    fn listener_rejects_old_srt_version() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        let mut cif = valid_conclusion(&l, t0);
        cif.extensions = vec![HsExtension::HsReq(HsExtFields {
            srt_version: 0x0001_0200, // pre-HSv5 feature level
            flags: HsFlags::live_defaults(),
            recv_latency_ms: 120,
            send_latency_ms: 0,
        })];
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::ROGUE);
    }

    #[test]
    fn listener_congestion_live_ok_file_rejected() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());

        let mut cif = valid_conclusion(&l, t0);
        cif.extensions.push(HsExtension::Congestion("live".into()));
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_CONFIG;
        assert!(matches!(
            handle(&mut l, t0, &cif),
            ListenerAction::Accept { .. }
        ));

        let mut cif = valid_conclusion(&l, t0);
        cif.extensions.push(HsExtension::Congestion("file".into()));
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_CONFIG;
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::CONGESTION);
    }

    #[test]
    fn listener_rejects_filter_skips_group() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());

        let mut cif = valid_conclusion(&l, t0);
        cif.extensions.push(HsExtension::Unknown {
            cmd: SRT_CMD_FILTER,
            data: vec![0; 8],
        });
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_CONFIG;
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::FILTER);

        let mut cif = valid_conclusion(&l, t0);
        cif.extensions.push(HsExtension::Unknown {
            cmd: SRT_CMD_GROUP,
            data: vec![0; 8],
        });
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_CONFIG;
        assert!(matches!(
            handle(&mut l, t0, &cif),
            ListenerAction::Accept { .. }
        ));
    }

    // -- SYN cookie -------------------------------------------------------------

    #[test]
    fn cookie_is_deterministic_and_input_sensitive() {
        let t0 = Instant::now();
        let l = listener(t0, SrtOptions::default());
        let c1 = l.cookie(t0, caller_addr());
        assert_eq!(c1, l.cookie(t0, caller_addr()));
        // Same secret + start → same cookie across instances (stateless).
        let l2 = Listener::new(SECRET, Timebase::new(t0), SrtOptions::default());
        assert_eq!(c1, l2.cookie(t0, caller_addr()));
        // Different port, ip, minute or secret → different cookie.
        let other_port = SocketAddrV4::new(*caller_addr().ip(), 50_001);
        assert_ne!(c1, l.cookie(t0, other_port));
        let other_ip = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 50_000);
        assert_ne!(c1, l.cookie(t0, other_ip));
        assert_ne!(c1, l.cookie(t0 + Duration::from_secs(60), caller_addr()));
        let l3 = Listener::new(SECRET + 1, Timebase::new(t0), SrtOptions::default());
        assert_ne!(c1, l3.cookie(t0, caller_addr()));
        // Stable within the same minute.
        assert_eq!(c1, l.cookie(t0 + Duration::from_secs(59), caller_addr()));
    }

    #[test]
    fn cookie_accepted_across_minute_boundary() {
        let t0 = Instant::now();
        let mut l = listener(t0, SrtOptions::default());
        // Induction answered at 59 s (minute 0)...
        let t_ind = t0 + Duration::from_secs(59);
        let cookie = l.cookie(t_ind, caller_addr());
        // ...conclusion lands at 61 s (minute 1): previous-minute cookie OK.
        let t_conc = t0 + Duration::from_secs(61);
        let mut cif = valid_conclusion(&l, t0);
        cif.cookie = cookie;
        assert!(matches!(
            handle(&mut l, t_conc, &cif),
            ListenerAction::Accept { .. }
        ));
        // Two minutes stale: dropped.
        let t_late = t0 + Duration::from_secs(121);
        assert!(matches!(handle(&mut l, t_late, &cif), ListenerAction::Drop));
    }

    #[test]
    fn cookie_check_direct() {
        let t0 = Instant::now();
        let l = listener(t0, SrtOptions::default());
        let cookie = l.cookie(t0, caller_addr());
        assert!(l.cookie_ok(t0, caller_addr(), cookie));
        assert!(l.cookie_ok(t0 + Duration::from_secs(59), caller_addr(), cookie));
        assert!(l.cookie_ok(t0 + Duration::from_secs(61), caller_addr(), cookie));
        assert!(!l.cookie_ok(t0 + Duration::from_secs(121), caller_addr(), cookie));
        assert!(!l.cookie_ok(t0, caller_addr(), cookie.wrapping_add(1)));
        // A cookie for peer A never validates for peer B.
        let other = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 50_000);
        assert!(!l.cookie_ok(t0, other, cookie));
    }

    #[test]
    fn listener_accept_reply_and_negotiated_consistent() {
        let t0 = Instant::now();
        let lopts = SrtOptions {
            mss: 1400,
            ..SrtOptions::default().latency(Duration::from_millis(200))
        };
        let mut l = listener(t0, lopts);
        let cif = valid_conclusion(&l, t0);
        let (reply, neg) = match handle(&mut l, t0, &cif) {
            ListenerAction::Accept { reply, negotiated } => (reply, *negotiated),
            _ => panic!("expected Accept"),
        };
        let rcif = hs_cif(&reply);
        // HSRSP latencies mirror the negotiated values, halves per §4.2.
        let hsrsp = rcif.hs_ext().expect("HSRSP");
        assert_eq!(hsrsp.recv_latency_ms, 200); // max(200, HSREQ snd 0)
        assert_eq!(hsrsp.send_latency_ms, 120); // max(0, HSREQ rcv 120)
        assert_eq!(neg.rcv_latency, Duration::from_millis(200));
        assert_eq!(neg.snd_latency, Duration::from_millis(120));
        assert_eq!(rcif.mss, 1400);
        assert_eq!(neg.mss, 1400);
        assert_eq!(neg.local_socket_id, ACCEPT_ID);
        assert_eq!(neg.peer_socket_id, CALLER_ID);
        assert_eq!(neg.send_initial_seq, CALLER_ISN);
        assert_eq!(neg.recv_initial_seq, CALLER_ISN);
        assert_eq!(neg.flow_window, 8192);
    }
}
