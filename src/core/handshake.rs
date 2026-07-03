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
//!
//! KMX (docs/spec/encryption.md §6): the caller is always the initiator —
//! with a passphrase it attaches its KMREQ to the CONCLUSION request and
//! judges the KMRSP in the response; the listener (responder) unwraps the
//! KMREQ and echoes it in the same CONCLUSION response. Encryption is
//! always enforced (§8): every mismatch or KMX failure rejects the
//! handshake — the §8 non-enforced rows are not implemented; a secured
//! handshake puts the engine in [`Negotiated::crypto`].

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
    crypto::{
        Crypto,
        CryptoConfig,
        KeyLength,
        KmRspOutcome,
        KmState,
    },
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
///
/// Not `Clone`: [`Negotiated::crypto`] owns key material.
#[derive(Debug)]
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
    /// Encryption engine seeded by the handshake KMX (encryption.md §6):
    /// `Some` when key material was exchanged; `None` for an unencrypted
    /// connection. Encryption is always enforced (§8): KMX mismatches and
    /// failures reject the handshake instead of producing a degraded
    /// context — the one exception is the §6.3 1-word UNSECURED report,
    /// after which even libsrt's enforced caller connects (the engine
    /// keeps the failure states and gates its own traffic on them).
    pub crypto: Option<Crypto>,
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
    /// Resolved crypto options; consumed at the induction→conclusion
    /// transition (after the §7 PBKEYLEN adoption) to seed `crypto`.
    crypto_cfg: Option<CryptoConfig>,
    /// KMX engine — the caller is always the initiator (encryption.md §1).
    /// Created before the first CONCLUSION request (§6.1); moves into
    /// [`Negotiated`] at establishment.
    crypto: Option<Crypto>,
    /// Encryption Field advert for the CONCLUSION request (§7): the raw
    /// configured PBKEYLEN (0 = unset) after the induction-time adoption,
    /// mirroring `m_config.iSndCryptoKeyLen` (`core.cpp:1454`) — never
    /// the resolved key length of the key material.
    enc_advert: u16,
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
        // Crypto options are validated by the runtime before connecting
        // (like the StreamID length). If an invalid set reaches the FSM
        // anyway, fail closed: never handshake unencrypted when the user
        // asked for encryption — the Failed state transmits nothing.
        let (crypto_cfg, state) = match opts.crypto_config() {
            Ok(cfg) => (cfg, CallerState::Induction),
            Err(err) => {
                warn!(%err, "invalid crypto options; caller handshake aborted");
                (None, CallerState::Failed)
            }
        };
        CallerHandshake {
            remote,
            local_socket_id,
            initial_seq,
            timebase,
            opts: opts.clone(),
            state,
            next_send: now,
            deadline: now + opts.connect_timeout,
            crypto_cfg,
            crypto: None,
            enc_advert: 0,
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
            let encrypting = self.crypto.is_some() || self.crypto_cfg.is_some();
            return self.fail(reject_error(code, encrypting));
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
        // §7: adopt the listener's PBKEYLEN advert (Encryption Field of the
        // induction response), then generate the key material that rides in
        // the CONCLUSION request (§6.1) — the caller is the KMX initiator.
        if let Some(cfg) = self.crypto_cfg.as_mut() {
            adopt_peer_pbkeylen(cfg, cif.encryption, self.opts.pbkeylen.is_some());
        }
        // `checkUpdateCryptoKeyLen` writes the adoption back into the raw
        // config value (`m_config.iSndCryptoKeyLen`, core.cpp:4744/4757),
        // passphrase or not, and the CONCLUSION advert carries exactly that
        // raw value (core.cpp:1454) — 0 when PBKEYLEN stays unset on both
        // ends; the 0→16 default is confined to the crypto engine (§7
        // "unset→0", crypto.cpp:596-599).
        if let Some(peer) = pbkeylen_from_bits(cif.encryption) {
            self.opts.pbkeylen = Some(peer);
        }
        self.enc_advert = self.opts.pbkeylen.map_or(0, pbkeylen_bits);
        self.crypto = self.crypto_cfg.take().map(Crypto::new_initiator);
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
        // -- KMX outcome (encryption.md §6.1, §6.3, §8) --
        let km_rsp = cif.extensions.iter().find_map(|e| match e {
            HsExtension::KmRsp(data) => Some(data.as_slice()),
            _ => None,
        });
        if let Some(crypto) = self.crypto.as_mut() {
            match km_rsp.map(|payload| crypto.handle_kmrsp(payload)) {
                // §6.3: the byte-exact echo of our KMREQ — both directions
                // are SECURED with the one SEK (§1).
                Some(KmRspOutcome::Confirmed) => {
                    debug!("handshake KMX confirmed; connection secured");
                }
                // §6.3: a 1-word UNSECURED report returns 0 — even an
                // enforced caller connects. The engine keeps the states and
                // gates its own KM traffic on the UNSECURED snd state.
                Some(KmRspOutcome::Failed(KmState::Unsecured)) => {
                    warn!("peer reports no crypto; continuing");
                }
                // Failure status, mismatched echo or no KMRSP at all —
                // libsrt's processSrtMsg_KMRSP −1 class. §6.1: the caller
                // aborts LOCALLY, always with UNSECURE (even for a bad
                // secret), and sends nothing — the listener's accepted
                // socket dies by its own timeout. §8 rows 4/11 (non-enforced
                // continue-with-own-SEK) are not implemented —
                // always-enforced library, the connection is rejected
                // instead.
                outcome => {
                    warn!(?outcome, "handshake KMX failed; aborting (enforced encryption)");
                    return self.fail(SrtError::Rejected(reject::UNSECURE));
                }
            }
        } else if cif
            .extensions
            .iter()
            .any(|e| matches!(e, HsExtension::KmReq(_) | HsExtension::KmRsp(_)))
        {
            // §8 row 6: the peer runs encryption, we have no passphrase.
            // Row 7 (non-enforced ignore-and-connect) is not implemented —
            // always-enforced library, the connection is rejected instead.
            warn!("conclusion response carries key material; aborting (enforced encryption)");
            return self.fail(SrtError::EncryptionUnsupported);
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
            crypto: self.crypto.take(),
        };
        debug!(
            peer = ?negotiated.peer_socket_id,
            mss = negotiated.mss,
            rcv_latency = ?negotiated.rcv_latency,
            snd_latency = ?negotiated.snd_latency,
            secured = negotiated.crypto.is_some(),
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
        // §6.1: the initial KM message rides in the CONCLUSION request and
        // is re-attached byte-identically on every handshake retransmission
        // (wire order HSREQ, SID, KMREQ — docs/spec/handshake.md §5.3).
        if let Some(kmreq) = self.crypto.as_ref().and_then(Crypto::kmreq) {
            extension_field |= HS_EXT_KMREQ;
            extensions.push(HsExtension::KmReq(kmreq));
        }
        HandshakeCif {
            version: HS_VERSION_SRT1,
            encryption: self.enc_advert, // §7 PBKEYLEN advert
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
/// conclusion needs to be validated is carried in the SYN cookie (a
/// repeated CONCLUSION re-derives the identical KMX answer from the
/// caller's KMREQ, encryption.md §6.2).
pub struct Listener {
    secret: u64,
    timebase: Timebase,
    opts: SrtOptions,
    /// Crypto options resolved once (encryption.md §2); `Err(())` = the
    /// set is locally invalid — the runtime validates up front, and if a
    /// bad set reaches this far every conclusion is rejected (fail
    /// closed: never accept a connection the user meant to secure).
    crypto_cfg: Result<Option<CryptoConfig>, ()>,
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
        let crypto_cfg = opts.crypto_config().map_err(|err| {
            warn!(%err, "invalid crypto options; listener will reject all conclusions");
        });
        Listener {
            secret,
            timebase,
            opts,
            crypto_cfg,
        }
    }

    /// Handles a handshake packet from an unknown peer.
    ///
    /// `new_socket_id` / `new_initial_seq` are the identifiers to assign if
    /// this packet completes a connection (the runtime provides fresh random
    /// values on every call; they are only consumed on `Accept`).
    ///
    /// KMX follows the encryption.md §8 matrix, always enforced: with a
    /// local passphrase a valid KMREQ is unwrapped and echoed (KMRSP) and
    /// `Negotiated.crypto` is populated; mismatches reject
    /// (`reject::UNSECURE` / `reject::BADSECRET`). The §8 non-enforced
    /// rows (1-word status KMRSP + fake TX context) are not implemented —
    /// always-enforced library, the connection is rejected instead.
    /// Rendezvous (WAVEAHAND) is dropped; HSv4 conclusions are rejected
    /// with `reject::VERSION`.
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
        // §7: the listener advertises its configured PBKEYLEN here (raw
        // option value — 0 when unset, even with a passphrase).
        reply.encryption = self.opts.pbkeylen.map_or(0, pbkeylen_bits);
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
        // The advertised-PBKEYLEN half of the type word alone is never a
        // problem: a responder adopts the KMREQ's key length anyway
        // (encryption.md §7) — pbkeylen without a passphrase is legal.
        if cif.encryption != 0 && !has_km {
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
        // -- KMX (encryption.md §6.2, §8) --
        let Ok(crypto_cfg) = &self.crypto_cfg else {
            // Locally invalid crypto options: fail closed (see field doc).
            warn!(%from, "invalid local crypto options; rejecting");
            return self.rejection(now, cif, reject::UNSECURE);
        };
        let kmreq = cif.extensions.iter().find_map(|e| match e {
            HsExtension::KmReq(data) => Some(data.as_slice()),
            _ => None,
        });
        let (crypto, km_rsp): (Option<Crypto>, Option<Vec<u8>>) = match (crypto_cfg, kmreq) {
            // §8 row 1: no encryption anywhere — the KMRSP block is
            // omitted entirely (§6.2).
            (None, None) => (None, None),
            // §8 row 2 [wire-verified]: KMREQ without a local
            // passphrase. Rows 3/4 (non-enforced 1-word NOSECRET KMRSP)
            // are not implemented — always-enforced library, the
            // connection is rejected instead.
            (None, Some(_)) => {
                warn!(%from, "caller requires encryption, no local passphrase; rejecting");
                return self.rejection(now, cif, reject::UNSECURE);
            }
            // §8 row 5: local passphrase but no KMX from the caller —
            // the "Agent declares encryption, but Peer does not" check.
            // Rows 6/7 (non-enforced 1-word UNSECURED KMRSP + §6.2
            // step 6 fake TX context) are not implemented —
            // always-enforced library, the connection is rejected
            // instead.
            (Some(_), None) => {
                warn!(%from, "local passphrase but caller sent no KMREQ; rejecting");
                return self.rejection(now, cif, reject::UNSECURE);
            }
            (Some(cfg), Some(km)) => match Crypto::new_responder(cfg.clone(), km) {
                // §8 row 8: echo the received KM message byte-for-byte
                // (§6.2 step 4); the caller's one SEK now secures both
                // directions (§1).
                Ok((crypto, echo)) => {
                    debug!(%from, kmreq_len = km.len(), "handshake KMX succeeded");
                    (Some(crypto), Some(echo))
                }
                // §8 row 9 [wire-verified]: BADSECRET only when the
                // failure was BADSECRET class (pre-checks / unwrap ICV
                // = wrong passphrase), UNSECURE for the NOSECRET class.
                // Rows 10/11 (non-enforced 1-word failure-status KMRSP +
                // fake TX context) are not implemented — always-enforced
                // library, the connection is rejected instead.
                Err(state) => {
                    warn!(%from, ?state, "handshake KMX failed; rejecting");
                    let code = if state == KmState::BadSecret {
                        reject::BADSECRET
                    } else {
                        reject::UNSECURE
                    };
                    return self.rejection(now, cif, code);
                }
            },
        };
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
            crypto,
        };
        let mut extensions = vec![HsExtension::HsRsp(HsExtFields {
            srt_version: SRT_VERSION,
            flags: HsFlags::live_defaults(),
            recv_latency_ms: ms_u16(rcv_latency),
            send_latency_ms: ms_u16(snd_latency),
        })];
        let mut extension_field = HS_EXT_HSREQ;
        if let Some(payload) = km_rsp {
            // The KMRSP rides in the same CONCLUSION response as the HSRSP
            // (§6.2, timing §13), after it on the wire (handshake.md §5.4).
            extension_field |= HS_EXT_KMREQ;
            extensions.push(HsExtension::KmRsp(payload));
        }
        let reply_cif = HandshakeCif {
            version: HS_VERSION_SRT1,
            // §7 / core.cpp:1454: the raw configured PBKEYLEN (0 = unset),
            // exactly like the induction response — never the KMREQ-adopted
            // key length (`checkUpdateCryptoKeyLen` never runs on the
            // listener's conclusion path).
            encryption: self.opts.pbkeylen.map_or(0, pbkeylen_bits),
            extension_field,
            initial_seq: cif.initial_seq, // echoed: the caller aborts on mismatch
            mss,
            flow_window: self.opts.flow_window,
            handshake_type: HandshakeType::Conclusion,
            socket_id: new_socket_id, // becomes the caller's peer id
            cookie: cif.cookie,       // echoed like libsrt; callers ignore it
            peer_ip: HandshakeCif::encode_peer_ip(*from.ip()),
            extensions,
        };
        debug!(
            %from,
            peer = ?cif.socket_id,
            local = ?new_socket_id,
            ?rcv_latency,
            ?snd_latency,
            mss,
            secured = negotiated.crypto.is_some(),
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

/// Maps a wire rejection code to the public error. Without a local
/// passphrase an UNSECURE rejection means "the listener demands
/// encryption"; with one it means the listener could not do encryption
/// (§8 rows 2/9) and surfaces as a plain rejection.
fn reject_error(code: u32, encrypting: bool) -> SrtError {
    if code == reject::UNSECURE && !encrypting {
        SrtError::EncryptionUnsupported
    } else {
        SrtError::Rejected(code)
    }
}

/// CIF Encryption Field advert for a PBKEYLEN (encryption.md §7,
/// `handshake.h:SrtHSRequest::wrapFlags`): 16 → 2, 24 → 3, 32 → 4.
fn pbkeylen_bits(len: KeyLength) -> u16 {
    match len {
        KeyLength::Aes128 => 2,
        KeyLength::Aes192 => 3,
        KeyLength::Aes256 => 4,
    }
}

/// Inverse of [`pbkeylen_bits`]: `None` for 0 (unset) and for the 1/5/6/7
/// values libsrt ignores as IPE (§7).
fn pbkeylen_from_bits(bits: u16) -> Option<KeyLength> {
    match bits {
        2 => Some(KeyLength::Aes128),
        3 => Some(KeyLength::Aes192),
        4 => Some(KeyLength::Aes256),
        _ => None,
    }
}

/// §7 caller-side adoption (`core.cpp:checkUpdateCryptoKeyLen`): a 2/3/4
/// advert in the listener's induction response replaces the local
/// PBKEYLEN — adopted outright when ours is unset, peer-wins when both
/// are set and differ (this library has no SRTO_SENDER, matching libsrt's
/// default); 0 keeps our value; anything else is ignored (libsrt logs an
/// IPE).
fn adopt_peer_pbkeylen(cfg: &mut CryptoConfig, advert: u16, own_set: bool) {
    match pbkeylen_from_bits(advert) {
        Some(peer) if peer != cfg.key_len => {
            if own_set {
                warn!(?peer, local = ?cfg.key_len, "peer advertises a different PBKEYLEN; peer wins");
            } else {
                debug!(?peer, "adopting the listener's advertised PBKEYLEN");
            }
            cfg.key_len = peer;
        }
        Some(_) => {}
        None if advert == 0 => {}
        None => warn!(advert, "invalid PBKEYLEN advert ignored"),
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

    fn accept_of(action: ListenerAction) -> (Packet, Negotiated) {
        match action {
            ListenerAction::Accept { reply, negotiated } => (reply, *negotiated),
            ListenerAction::Reply(p) => {
                panic!("expected Accept, got Reply({:?})", hs_cif(&p).handshake_type)
            }
            ListenerAction::Drop => panic!("expected Accept, got Drop"),
        }
    }

    fn km_req_of(cif: &HandshakeCif) -> &[u8] {
        cif.extensions
            .iter()
            .find_map(|e| match e {
                HsExtension::KmReq(data) => Some(data.as_slice()),
                _ => None,
            })
            .expect("KMREQ attached")
    }

    fn km_rsp_of(cif: &HandshakeCif) -> &[u8] {
        cif.extensions
            .iter()
            .find_map(|e| match e {
                HsExtension::KmRsp(data) => Some(data.as_slice()),
                _ => None,
            })
            .expect("KMRSP attached")
    }

    const PASSPHRASE: &str = "correct horse battery";
    const WRONG_PASSPHRASE: &str = "wrong horse battery";

    fn secure_opts() -> SrtOptions {
        SrtOptions::default().passphrase(PASSPHRASE)
    }

    /// Drives a real caller/listener pair up to the caller's CONCLUSION
    /// request (KMREQ attached if `caller_opts` has a passphrase); the
    /// test then decides what the listener/caller does with it.
    fn exchange_to_conclusion(
        caller_opts: SrtOptions,
        listener_opts: SrtOptions,
    ) -> (Instant, CallerHandshake, Listener, HandshakeCif) {
        let t0 = Instant::now();
        let mut c = caller(t0, &caller_opts);
        let mut l = listener(t0, listener_opts);
        let ind = c.poll_transmit(t0).expect("induction request");
        let rsp = reply_of(l.handle_handshake(t0, caller_addr(), hs_cif(&ind), ACCEPT_ID, UNUSED_ISN));
        assert!(c
            .handle_handshake(t0, hs_cif(&rsp))
            .expect("induction ok")
            .is_none());
        let conc = c.poll_transmit(t0).expect("conclusion request");
        let cif = hs_cif(&conc).clone();
        (t0, c, l, cif)
    }

    /// Runs the full caller<->listener exchange, asserting the wire-visible
    /// invariants along the way, and returns both `Negotiated`.
    ///
    /// Only for option sets that connect (§8 rows 1/8 — the only
    /// connecting rows of an always-enforced library); rejection rows get
    /// dedicated tests.
    fn run_exchange(
        caller_opts: SrtOptions,
        listener_opts: SrtOptions,
    ) -> (Negotiated, Negotiated) {
        let t0 = Instant::now();
        let mut c = caller(t0, &caller_opts);
        let mut l = listener(t0, listener_opts.clone());
        // Expected caller-side key length after the §7 adoption: a 2/3/4
        // advert from the listener wins, otherwise the caller's own
        // (resolved) setting stands.
        let c_cfg = caller_opts.crypto_config().expect("valid crypto options");
        let expect_klen = c_cfg
            .as_ref()
            .map(|cfg| listener_opts.pbkeylen.unwrap_or(cfg.key_len));

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
        // §7: the listener advertises its configured PBKEYLEN (0 = unset).
        assert_eq!(rsp.encryption, listener_opts.pbkeylen.map_or(0, pbkeylen_bits));
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
        // §7 "unset→0" / core.cpp:1454: the CONCLUSION advert is the RAW
        // configured PBKEYLEN after the induction-time adoption (a 2/3/4
        // listener advert replaces the local value) — never the resolved
        // key length of the key material.
        let expect_advert = listener_opts.pbkeylen.or(caller_opts.pbkeylen);
        assert_eq!(req.encryption, expect_advert.map_or(0, pbkeylen_bits));
        assert_eq!(req.handshake_type, HandshakeType::Conclusion);
        assert_eq!(req.cookie, cookie); // echoed verbatim
        assert_eq!(req.socket_id, CALLER_ID);
        assert_eq!(req.initial_seq, CALLER_ISN);
        let mut expect_ext = HS_EXT_HSREQ;
        if caller_opts.streamid.is_some() {
            expect_ext |= HS_EXT_CONFIG;
        }
        if expect_klen.is_some() {
            expect_ext |= HS_EXT_KMREQ;
        }
        assert_eq!(req.extension_field, expect_ext);
        let hsreq = req.hs_ext().expect("HSREQ attached");
        assert_eq!(hsreq.srt_version, SRT_VERSION);
        assert_eq!(hsreq.flags, HsFlags::live_defaults());
        assert_eq!(hsreq.recv_latency_ms, ms_u16(caller_opts.latency));
        assert_eq!(hsreq.send_latency_ms, ms_u16(caller_opts.peer_latency));
        assert_eq!(req.stream_id(), caller_opts.streamid.as_deref());
        match expect_klen {
            // §3: single-key KM message length pins the SEK length.
            Some(klen) => assert_eq!(km_req_of(req).len(), 16 + 16 + 8 + klen.bytes()),
            None => assert!(!req
                .extensions
                .iter()
                .any(|e| matches!(e, HsExtension::KmReq(_)))),
        }

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
        // The response advert is the listener's raw option too (its
        // `m_config` is never mutated on this path — core.cpp:1454).
        assert_eq!(rsp.encryption, listener_opts.pbkeylen.map_or(0, pbkeylen_bits));
        assert_eq!(rsp.initial_seq, CALLER_ISN); // adopted + echoed
        assert_eq!(rsp.socket_id, ACCEPT_ID);
        // §6.2: a KMRSP block (echo or 1-word status) is attached whenever
        // either side runs encryption; omitted only when neither does.
        let expect_kmrsp = c_cfg.is_some()
            || listener_opts
                .crypto_config()
                .expect("valid crypto options")
                .is_some();
        let expect_ext = if expect_kmrsp {
            HS_EXT_HSREQ | HS_EXT_KMREQ
        } else {
            HS_EXT_HSREQ
        };
        assert_eq!(rsp.extension_field, expect_ext);
        assert_eq!(
            rsp.extensions
                .iter()
                .any(|e| matches!(e, HsExtension::KmRsp(_))),
            expect_kmrsp
        );
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
        // §8 row 1: no KMX blocks, no crypto anywhere.
        assert!(c_neg.crypto.is_none());
        assert!(l_neg.crypto.is_none());
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
        caller_in_conclusion_with(t0, SrtOptions::default())
    }

    /// [`caller_in_conclusion`] with explicit options.
    fn caller_in_conclusion_with(t0: Instant, opts: SrtOptions) -> (CallerHandshake, u32) {
        let cookie = 0x5EED_C00C;
        let mut c = caller(t0, &opts);
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
        // An UNSECURE (1011) rejection while we have no passphrase means
        // "the listener demands crypto" (§8 row 5, caller side).
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
        // §8 rows 6/7 shape: KM material in the response while we have no
        // passphrase — the caller aborts locally (row 7's non-enforced
        // ignore-and-connect is not implemented — always-enforced
        // library, the connection is rejected instead).
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion(t0);
        let mut rsp = conclusion_response();
        rsp.extensions.push(HsExtension::KmRsp(vec![0, 0, 0, 3]));
        rsp.extension_field = HS_EXT_HSREQ | HS_EXT_KMREQ;
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::EncryptionUnsupported)
        ));
        // §6.1: local abort — nothing is sent to the listener.
        assert!(c.poll_transmit(t0 + HS_RETRY_INTERVAL).is_none());
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
        // §8 row 2 [wire-verified]: KMREQ arrives, no local passphrase —
        // UNSECURE regardless of the KM content.
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

    // -- KMX: §8 enforcement matrix ------------------------------------------

    /// Encrypts on `tx`, decrypts on `rx`, asserting the payload survives.
    fn crypto_roundtrip(tx: &mut Crypto, rx: &mut Crypto, n: u32) {
        let clear: Vec<u8> = (0 .. 64).map(|i| i as u8 ^ n as u8).collect();
        let mut buf = clear.clone();
        let flags = tx.encrypt(SeqNumber::new(n), &mut buf);
        assert_ne!(buf, clear, "payload must be transformed");
        rx.decrypt(SeqNumber::new(n), flags, &mut buf)
            .expect("decrypt must succeed");
        assert_eq!(buf, clear, "payload must survive the roundtrip");
    }

    #[test]
    fn matrix_row8_kmx_secures_both_directions() {
        let (c_neg, l_neg) = run_exchange(secure_opts(), secure_opts());
        let mut c = c_neg.crypto.expect("caller secured");
        let mut l = l_neg.crypto.expect("listener secured");
        for crypto in [&c, &l] {
            assert_eq!(crypto.snd_km_state(), KmState::Secured);
            assert_eq!(crypto.rcv_km_state(), KmState::Secured);
        }
        // §1: the caller's one SEK serves both directions.
        crypto_roundtrip(&mut c, &mut l, 42);
        crypto_roundtrip(&mut l, &mut c, 43);
        // Confirmed by the handshake KMRSP: nothing left to retry.
        assert!(c.kmreq().is_none());
    }

    #[test]
    fn matrix_row8_kmrsp_echoes_kmreq_bytes() {
        // §6.2 step 4 / §6.3 trap: the success KMRSP is the received KMREQ
        // byte-for-byte; the caller validates it by memcmp.
        let (t0, mut c, mut l, req) = exchange_to_conclusion(secure_opts(), secure_opts());
        let kmreq = km_req_of(&req).to_vec();
        let (reply, l_neg) = accept_of(handle(&mut l, t0, &req));
        let rcif = hs_cif(&reply);
        assert_eq!(km_rsp_of(rcif), &kmreq[..]);
        assert_eq!(rcif.extension_field, HS_EXT_HSREQ | HS_EXT_KMREQ);
        assert_eq!(rcif.encryption, 0); // §7: raw PBKEYLEN (unset), core.cpp:1454
        assert!(l_neg.crypto.is_some());
        let c_neg = c
            .handle_handshake(t0, rcif)
            .expect("conclusion ok")
            .expect("established");
        assert!(c_neg.crypto.is_some());
    }

    #[test]
    fn matrix_row2_enforced_listener_without_passphrase_rejects() {
        let (t0, mut c, mut l, req) = exchange_to_conclusion(secure_opts(), SrtOptions::default());
        let reply = reply_of(l.handle_handshake(t0, caller_addr(), &req, ACCEPT_ID, UNUSED_ISN));
        let rcif = hs_cif(&reply);
        // §8.1 [wire-verified]: UNSECURE = handshake type 1011.
        assert_eq!(rcif.handshake_type, HandshakeType::Rejection(reject::UNSECURE));
        // With a passphrase the caller surfaces the plain wire code (the
        // listener cannot do encryption — not "encryption unsupported").
        assert!(matches!(
            c.handle_handshake(t0, rcif),
            Err(SrtError::Rejected(code)) if code == reject::UNSECURE
        ));
    }

    #[test]
    fn matrix_rows3_4_nosecret_kmrsp_from_permissive_peer_aborts() {
        // §8 rows 3/4, caller side: a permissive no-passphrase peer (not
        // this library — the non-enforced rows are not implemented; e.g.
        // libsrt with SRTO_ENFORCEDENCRYPTION=false) answers our KMREQ
        // with the 1-word NOSECRET(3) status (§6.2 step 3; LE per §5.1).
        // §6.1: the caller aborts LOCALLY, always with UNSECURE, and
        // sends nothing — the peer's socket times out.
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion_with(t0, secure_opts());
        let mut rsp = conclusion_response();
        rsp.extensions.push(HsExtension::KmRsp(vec![3, 0, 0, 0]));
        rsp.extension_field = HS_EXT_HSREQ | HS_EXT_KMREQ;
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::Rejected(code)) if code == reject::UNSECURE
        ));
        assert!(c.poll_transmit(t0 + HS_RETRY_INTERVAL).is_none());
    }

    #[test]
    fn matrix_row5_enforced_listener_with_passphrase_rejects_plain_caller() {
        // "Agent declares encryption, but Peer does not" (§6.2 post-check).
        let t0 = Instant::now();
        let mut l = listener(t0, secure_opts());
        let cif = valid_conclusion(&l, t0);
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::UNSECURE);
    }

    #[test]
    fn matrix_rows6_7_plain_caller_secured_listener_rejected_end_to_end() {
        // §8 rows 6/7 (non-enforced 1-word UNSECURED KMRSP + §6.2 step 6
        // fake TX context) are not implemented — always-enforced library:
        // the listener rejects the KMREQ-less caller with UNSECURE
        // (row 5) and the passphrase-less caller surfaces it as
        // "the peer demands encryption".
        let (t0, mut c, mut l, req) = exchange_to_conclusion(SrtOptions::default(), secure_opts());
        assert!(!req.extensions.iter().any(|e| matches!(e, HsExtension::KmReq(_))));
        let reply = reply_of(handle(&mut l, t0, &req));
        let rcif = hs_cif(&reply);
        assert_eq!(rcif.handshake_type, HandshakeType::Rejection(reject::UNSECURE));
        assert!(matches!(
            c.handle_handshake(t0, rcif),
            Err(SrtError::EncryptionUnsupported)
        ));
    }

    #[test]
    fn matrix_row9_wrong_passphrase_rejected_badsecret() {
        let lopts = SrtOptions::default().passphrase(WRONG_PASSPHRASE);
        let (t0, mut c, mut l, req) = exchange_to_conclusion(secure_opts(), lopts);
        let reply = reply_of(l.handle_handshake(t0, caller_addr(), &req, ACCEPT_ID, UNUSED_ISN));
        let rcif = hs_cif(&reply);
        // §8.1 [wire-verified]: BADSECRET = handshake type 1010.
        assert_eq!(rcif.handshake_type, HandshakeType::Rejection(reject::BADSECRET));
        assert!(matches!(
            c.handle_handshake(t0, rcif),
            Err(SrtError::Rejected(code)) if code == reject::BADSECRET
        ));
    }

    #[test]
    fn matrix_rows10_11_badsecret_kmrsp_from_permissive_peer_aborts() {
        // §8 rows 10/11, caller side: a permissive peer whose unwrap
        // failed (not this library — the non-enforced rows are not
        // implemented) answers with the 1-word BADSECRET status (§5.1
        // trap [wire-verified]: `04 00 00 00` LE). The caller aborts
        // LOCALLY with UNSECURE — not BADSECRET — and sends nothing.
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion_with(t0, secure_opts());
        let mut rsp = conclusion_response();
        rsp.extensions.push(HsExtension::KmRsp(vec![4, 0, 0, 0]));
        rsp.extension_field = HS_EXT_HSREQ | HS_EXT_KMREQ;
        assert!(matches!(
            c.handle_handshake(t0, &rsp),
            Err(SrtError::Rejected(code)) if code == reject::UNSECURE
        ));
        assert!(c.poll_transmit(t0 + HS_RETRY_INTERVAL).is_none());
    }

    // -- KMX: caller details ----------------------------------------------------

    #[test]
    fn conclusion_kmreq_shape_and_retransmission() {
        let (t0, mut c, _l, req) = exchange_to_conclusion(secure_opts(), SrtOptions::default());
        assert_eq!(req.extension_field, HS_EXT_HSREQ | HS_EXT_KMREQ);
        assert_eq!(req.encryption, 0); // §7: raw PBKEYLEN (unset), not the default
        let km = km_req_of(&req).to_vec();
        assert_eq!(km.len(), 56); // §3: single key, KLen 16
        assert_eq!(km[0], 0x12); // Vers 1, PT KM
        assert_eq!(&km[1 .. 3], &[0x20, 0x29]); // 'HAI' sign
        assert_eq!(km[3], 0x01); // §9.1 trap: the first SEK is EVEN
        // §6.1: retransmissions re-attach the KMREQ byte-identically.
        let retry = c.poll_transmit(t0 + HS_RETRY_INTERVAL).expect("retransmit");
        assert_eq!(km_req_of(hs_cif(&retry)), &km[..]);
    }

    #[test]
    fn caller_with_passphrase_requires_kmrsp() {
        // A conclusion response with no KMRSP while our KMREQ is
        // outstanding (no libsrt listener does this): mirror of the
        // "Agent declares encryption, but Peer does not" check.
        let t0 = Instant::now();
        let (mut c, _) = caller_in_conclusion_with(t0, secure_opts());
        assert!(matches!(
            c.handle_handshake(t0, &conclusion_response()),
            Err(SrtError::Rejected(code)) if code == reject::UNSECURE
        ));
    }

    #[test]
    fn caller_kmrsp_echo_mismatch_aborts() {
        // A corrupted echo is libsrt's −1 class (§6.3): the caller
        // aborts with UNSECURE.
        let (t0, mut c, mut l, req) = exchange_to_conclusion(secure_opts(), secure_opts());
        let (reply, _) = accept_of(handle(&mut l, t0, &req));
        let mut rcif = hs_cif(&reply).clone();
        for ext in &mut rcif.extensions {
            if let HsExtension::KmRsp(data) = ext {
                data[20] ^= 0x01;
            }
        }
        assert!(matches!(
            c.handle_handshake(t0, &rcif),
            Err(SrtError::Rejected(code)) if code == reject::UNSECURE
        ));
    }

    // -- KMX: listener details ----------------------------------------------------

    #[test]
    fn listener_kmreq_failure_reject_codes() {
        // §6.2 [wire-verified]: BADSECRET only for the BADSECRET class
        // (srtcore pre-checks, unwrap ICV), UNSECURE for NOSECRET class.
        let t0 = Instant::now();
        let mut l = listener(t0, secure_opts());

        // Truncated KM (not longer than its header): pre-check ⇒ BADSECRET.
        let mut cif = valid_conclusion(&l, t0);
        cif.extensions.push(HsExtension::KmReq(vec![0x12; 16]));
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_KMREQ;
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::BADSECRET);

        // Structurally broken KM (bad sign): NOSECRET class ⇒ UNSECURE.
        let (t0, _c, mut l, mut req) = exchange_to_conclusion(secure_opts(), secure_opts());
        for ext in &mut req.extensions {
            if let HsExtension::KmReq(data) = ext {
                data[1] ^= 0xFF;
            }
        }
        assert_eq!(rejection_code(handle(&mut l, t0, &req)), reject::UNSECURE);
    }

    #[test]
    fn repeated_conclusion_kmx_is_reanswered_identically() {
        // §6.2/§10.4: repeated CONCLUSIONs are re-answered; the stateless
        // listener re-derives the identical echo and the identical SEK
        // from the caller's (byte-identical) KMREQ.
        let (t0, _c, mut l, req) = exchange_to_conclusion(secure_opts(), secure_opts());
        let (r1, n1) = accept_of(handle(&mut l, t0, &req));
        let (r2, n2) = accept_of(handle(&mut l, t0, &req));
        assert_eq!(km_rsp_of(hs_cif(&r1)), km_rsp_of(hs_cif(&r2)));
        let mut a = n1.crypto.expect("secured");
        let mut b = n2.crypto.expect("secured");
        crypto_roundtrip(&mut a, &mut b, 7);
    }

    // -- KMX: PBKEYLEN negotiation (§7) -----------------------------------------

    #[test]
    fn listener_advertises_configured_pbkeylen_in_induction() {
        let t0 = Instant::now();
        let mut l = listener(t0, secure_opts().pbkeylen(KeyLength::Aes192));
        let mut req = valid_conclusion(&l, t0);
        req.handshake_type = HandshakeType::Induction;
        req.version = 4;
        req.extension_field = 2;
        req.cookie = 0;
        req.extensions = vec![];
        let reply = reply_of(handle(&mut l, t0, &req));
        assert_eq!(hs_cif(&reply).encryption, 3); // 24-byte keys
    }

    #[test]
    fn caller_adopts_advertised_pbkeylen() {
        // Local PBKEYLEN unset → adopt the listener's induction advert.
        let lopts = secure_opts().pbkeylen(KeyLength::Aes256);
        let (_t0, _c, _l, req) = exchange_to_conclusion(secure_opts(), lopts);
        assert_eq!(req.encryption, 4);
        assert_eq!(km_req_of(&req)[15], 8); // KLen/4 = 8 → 32-byte SEK
    }

    #[test]
    fn caller_pbkeylen_peer_wins_on_conflict() {
        // Both set and different → the peer's advert wins (libsrt's
        // default; this library has no SRTO_SENDER).
        let copts = secure_opts().pbkeylen(KeyLength::Aes256);
        let lopts = secure_opts().pbkeylen(KeyLength::Aes128);
        let (_t0, _c, _l, req) = exchange_to_conclusion(copts, lopts);
        assert_eq!(req.encryption, 2);
        assert_eq!(km_req_of(&req)[15], 4);
    }

    #[test]
    fn caller_keeps_own_pbkeylen_on_zero_advert() {
        // Advertised 0 → keep our own setting.
        let copts = secure_opts().pbkeylen(KeyLength::Aes192);
        let (_t0, _c, _l, req) = exchange_to_conclusion(copts, secure_opts());
        assert_eq!(req.encryption, 3);
        assert_eq!(km_req_of(&req)[15], 6);
    }

    #[test]
    fn caller_ignores_junk_pbkeylen_advert() {
        // Advertised 1/5/6/7 → ignored like libsrt (logged IPE).
        let t0 = Instant::now();
        let mut c = caller(t0, &secure_opts());
        let _ = c.poll_transmit(t0).expect("induction");
        let rsp = HandshakeCif {
            version: 5,
            encryption: 5,
            extension_field: SRT_MAGIC,
            handshake_type: HandshakeType::Induction,
            cookie: 0x0C00_C1E5,
            extensions: vec![],
            ..conclusion_response()
        };
        assert!(c.handle_handshake(t0, &rsp).expect("continue").is_none());
        let conc = c.poll_transmit(t0).expect("conclusion");
        assert_eq!(hs_cif(&conc).encryption, 0); // raw PBKEYLEN stays unset
        assert_eq!(km_req_of(hs_cif(&conc))[15], 4); // key material: default 128
    }

    #[test]
    fn conclusion_advert_is_raw_pbkeylen_not_resolved() {
        // §7 "unset→0" / core.cpp:1454 [most common encrypted config]:
        // passphrases set, PBKEYLEN unset on both ends. libsrt puts the
        // raw config value (0) in the CONCLUSION type-word upper half in
        // BOTH directions — the 0→16 default lives only inside the crypto
        // engine (crypto.cpp:596-599) and is never written back.
        let (t0, _c, mut l, req) = exchange_to_conclusion(secure_opts(), secure_opts());
        assert_eq!(req.encryption, 0, "caller advert must be the raw option");
        assert_eq!(km_req_of(&req)[15], 4); // key material still AES-128
        let (reply, l_neg) = accept_of(handle(&mut l, t0, &req));
        assert_eq!(
            hs_cif(&reply).encryption,
            0,
            "listener advert must be the raw option, not the adopted KLen"
        );
        assert!(l_neg.crypto.is_some());
    }

    #[test]
    fn plain_caller_echoes_adopted_pbkeylen_advert() {
        // `checkUpdateCryptoKeyLen` runs on every HSv5 induction response,
        // passphrase or not (core.cpp:4439), and mutates the raw config:
        // a 2/3/4 advert is echoed back in the caller's CONCLUSION type
        // word even though no KMREQ is attached.
        let t0 = Instant::now();
        let mut c = caller(t0, &SrtOptions::default());
        let _ = c.poll_transmit(t0).expect("induction");
        let rsp = HandshakeCif {
            version: 5,
            encryption: 3, // listener configured with AES-192
            extension_field: SRT_MAGIC,
            handshake_type: HandshakeType::Induction,
            cookie: 0x0C00_C1E5,
            extensions: vec![],
            ..conclusion_response()
        };
        assert!(c.handle_handshake(t0, &rsp).expect("continue").is_none());
        let conc = c.poll_transmit(t0).expect("conclusion");
        assert_eq!(hs_cif(&conc).encryption, 3);
        assert!(!hs_cif(&conc)
            .extensions
            .iter()
            .any(|e| matches!(e, HsExtension::KmReq(_))));
    }

    #[test]
    fn listener_conclusion_advert_is_raw_option_when_set() {
        // A listener with an explicit PBKEYLEN adverts it in the
        // CONCLUSION response even when the KMX adopted a different key
        // length from the KMREQ (core.cpp:1454 uses m_config, which the
        // listener path never mutates).
        let t0 = Instant::now();
        let mut l = listener(t0, secure_opts().pbkeylen(KeyLength::Aes192));
        let mut cif = valid_conclusion(&l, t0);
        // A hand-rolled AES-128 KMREQ (the §7 induction adoption bypassed).
        let cfg = secure_opts()
            .crypto_config()
            .expect("valid crypto options")
            .expect("passphrase set");
        cif.extensions
            .push(HsExtension::KmReq(Crypto::new_initiator(cfg).kmreq().unwrap()));
        cif.extension_field = HS_EXT_HSREQ | HS_EXT_KMREQ;
        let (reply, l_neg) = accept_of(handle(&mut l, t0, &cif));
        assert_eq!(hs_cif(&reply).encryption, 3, "raw option, not adopted KLen 16");
        assert!(l_neg.crypto.is_some());
    }

    #[test]
    fn listener_adopts_kmreq_key_length_over_local_pbkeylen() {
        // §7 trap: the KMREQ's KLen silently overrides the responder's
        // PBKEYLEN — never a rejection. Advert 0 from the listener keeps
        // the caller's 32-byte choice; the listener adopts and echoes it.
        let copts = secure_opts().pbkeylen(KeyLength::Aes256);
        let (t0, mut c, mut l, req) = exchange_to_conclusion(copts, secure_opts());
        assert_eq!(km_req_of(&req)[15], 8);
        let (reply, l_neg) = accept_of(handle(&mut l, t0, &req));
        // core.cpp:1454: the response adverts the listener's raw option
        // (unset → 0), never the KLen adopted from the KMREQ.
        assert_eq!(hs_cif(&reply).encryption, 0);
        let mut l_crypto = l_neg.crypto.expect("secured");
        let c_neg = c
            .handle_handshake(t0, hs_cif(&reply))
            .expect("conclusion ok")
            .expect("established");
        let mut c_crypto = c_neg.crypto.expect("secured");
        crypto_roundtrip(&mut c_crypto, &mut l_crypto, 11);
        crypto_roundtrip(&mut l_crypto, &mut c_crypto, 12);
    }

    // -- KMX: invalid local options fail closed ----------------------------------

    #[test]
    fn invalid_crypto_options_fail_closed() {
        // The runtime validates crypto options up front; if an invalid set
        // reaches the FSM anyway, nothing must ever go out unencrypted.
        let t0 = Instant::now();
        let bad = SrtOptions::default().passphrase("short");
        let mut c = caller(t0, &bad);
        assert!(c.poll_transmit(t0).is_none(), "caller transmits nothing");
        assert_eq!(c.next_deadline(), None);

        let mut l = listener(t0, bad);
        let cif = valid_conclusion(&l, t0);
        assert_eq!(rejection_code(handle(&mut l, t0, &cif)), reject::UNSECURE);
    }
}
