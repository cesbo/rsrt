//! Layer 2 — sans-I/O connection core.
//!
//! [`Connection`] is a pure state machine: it never performs I/O, never
//! sleeps and never reads the clock — every input carries `now: Instant`.
//! The runtime layer (or a test harness with a fake clock) drives it:
//!
//! ```text
//! inputs:  handle_datagram / handle_timer / send / close
//! outputs: poll_transmit (packets out) / poll_deliver (payloads to app)
//! timing:  next_deadline → drive handle_timer at that instant
//! ```
//!
//! After *any* input, the driver must drain both `poll_transmit` and
//! `poll_deliver` until `None`.

pub mod handshake;
pub mod receiver;
pub mod sender;
pub mod time;

#[cfg(test)]
mod encrypted_sim_tests;
#[cfg(test)]
mod sim_tests;
#[cfg(test)]
mod tsbpd_stall_tests;

use std::{
    collections::VecDeque,
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

pub use self::{
    handshake::{
        CallerHandshake,
        Listener,
        ListenerAction,
        Negotiated,
    },
    receiver::{
        Receiver,
        ReceiverConfig,
    },
    sender::{
        Sender,
        SenderConfig,
    },
    time::Timebase,
};
use crate::{
    crypto::{
        Crypto,
        KmReqOutcome,
    },
    error::{
        CloseReason,
        SrtError,
    },
    options::SrtOptions,
    packet::{
        reject,
        ControlPacket,
        ControlType,
        DataPacket,
        EncryptionFlags,
        HandshakeType,
        Packet,
        PacketError,
        SeqNumber,
        SocketId,
        Timestamp,
    },
};

/// Keepalive interval on an idle send direction.
pub const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// `COMM_RESPONSE_MAX_EXP`: the peer-idle break additionally requires more
/// than this many EXP timer expirations (docs/spec/transmission.md §10).
const EXP_MAX_COUNT: u32 = 16;

/// EXP timer floor per expiration count: `EXPCount · 300 ms`.
const EXP_MIN_INTERVAL_US: u64 = 300_000;

/// Constant pad added to the RTT-based EXP period (10 ms).
const EXP_PAD_US: u64 = 10_000;

/// Data packets that arrived before the conclusion response are buffered up
/// to this count (docs/spec/handshake.md §5.5: data may race the response);
/// overflow is dropped — NAK recovery fetches it after establishment.
const EARLY_DATA_MAX: usize = 256;

/// Connection lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Caller handshake in progress.
    Connecting,
    Established,
    Closed(CloseReason),
}

/// Aggregated connection statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub pkts_sent: u64,
    pub pkts_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub pkts_retransmitted: u64,
    /// Sender-side too-late / overflow drops.
    pub pkts_send_dropped: u64,
    /// Receiver-side TSBPD skips (lost for good).
    pub pkts_recv_dropped: u64,
    /// Gaps detected on the receive path.
    pub pkts_recv_lost: u64,
    /// Undecryptable data packets received (docs/spec/encryption.md §9.4):
    /// each occupied its sequence slot and was ACKed, but is never delivered.
    pub undecrypted_pkts: u64,
    /// Completed TX key switches (docs/spec/encryption.md §10.1): how many
    /// times the send direction rotated to a refreshed SEK.
    pub km_refreshes: u64,
    pub rtt_us: u32,
    pub rtt_var_us: u32,
}

// One `State` lives per connection (never stored in collections), so boxing
// the large `Established` variant would add indirection for no gain.
#[allow(clippy::large_enum_variant)]
enum State {
    Connecting {
        hs: CallerHandshake,
        /// Application payloads queued before establishment.
        pending_send: VecDeque<Vec<u8>>,
        /// Data packets that raced ahead of the conclusion response,
        /// with their arrival instants (keeps the TSBPD anchor honest).
        early_data: VecDeque<(Instant, DataPacket)>,
    },
    Established {
        sender: Sender,
        receiver: Receiver,
        /// Encryption engine seeded by the handshake KMX
        /// ([`Negotiated::crypto`]); `None` on an unencrypted connection.
        crypto: Option<Crypto>,
    },
    Closed {
        reason: CloseReason,
        /// Kept so already-received data can still drain through
        /// `poll_deliver` after a peer SHUTDOWN (transmission.md §11).
        receiver: Option<Receiver>,
    },
}

/// A single SRT connection (either role), composed of the caller handshake
/// FSM (while connecting), then [`Sender`] + [`Receiver`].
///
/// Duties beyond delegation (docs/spec/transmission.md):
/// - stamp outgoing packets: timestamp from the local [`Timebase`], destination socket id = peer
///   socket id (0 during the handshake);
/// - route incoming packets: data → receiver; ACK/NAK → sender/receiver; ACKACK → receiver; DROPREQ
///   → receiver; SHUTDOWN → close; KEEPALIVE / CONGESTION-WARNING / PEERERROR → refresh liveness,
///   log; duplicate CONCLUSION handshake (listener side) → re-send the stored handshake reply;
///   undecodable datagrams → log, drop;
/// - data decryption (docs/spec/encryption.md §9.4): with a crypto context, payloads are decrypted
///   in place before the receiver sees them; an undecryptable packet (unkeyed SEK slot, or
///   KK ≠ None without any crypto context — packets.md §5.10) still occupies its sequence slot and
///   is ACKed, but is never delivered and never NAK-repaired — the connection stays up;
/// - key refresh (docs/spec/encryption.md §10, §11): `Crypto::on_ack` runs on the ACK-processing
///   path and its KMREQs go out as `UMSG_EXT`; incoming in-stream KMREQ/KMRSP feed the crypto
///   engine, failures answered per the §11.3 policy with total silence (encryption is always
///   enforced);
/// - keepalive: send KEEPALIVE after [`KEEPALIVE_INTERVAL`] without any outgoing packet;
/// - liveness: no packet from the peer for `peer_idle_timeout` → close with
///   [`CloseReason::PeerIdle`];
/// - data idle (optional): no data packet from the peer for `data_idle_timeout` → close with
///   [`CloseReason::DataIdle`] - keepalives and other control traffic do not count;
/// - on close (any reason): emit SHUTDOWN (best effort), drain state.
pub struct Connection {
    state: State,
    remote: SocketAddrV4,
    local_socket_id: SocketId,
    /// `SocketId::HANDSHAKE` (0) until the handshake completes.
    peer_socket_id: SocketId,
    timebase: Timebase,
    opts: SrtOptions,
    streamid: Option<String>,
    /// CONCLUSION response that accepted the peer (listener side); replayed
    /// verbatim whenever the peer repeats its CONCLUSION (lost response).
    hs_reply: Option<Packet>,
    /// Control packets owed to the peer (handshake reply, KEEPALIVE,
    /// SHUTDOWN); drained by `poll_transmit` ahead of sender/receiver output.
    transmit_q: VecDeque<Packet>,
    /// When anything was last put on the wire (keepalive timer base).
    last_sent: Instant,
    /// When anything was last received from the peer (liveness base).
    last_recv: Instant,
    /// When a data packet was last received from the peer; base for the
    /// optional data-idle check (`SrtOptions::data_idle_timeout`). Starts
    /// at connection establishment.
    last_data: Instant,
    /// EXP expiration counter (`EXPCount`); reset to 1 by any received
    /// packet, incremented by each EXP timer expiry.
    exp_count: u32,
    /// Stats snapshot frozen when the connection closed.
    closed_stats: Stats,
}

impl Connection {
    /// Opens a caller connection towards `remote`: queues the first
    /// INDUCTION request immediately.
    pub fn connect(
        now: Instant,
        remote: SocketAddrV4,
        local_socket_id: SocketId,
        initial_seq: SeqNumber,
        opts: SrtOptions,
    ) -> Connection {
        Self::connect_with_timebase(
            now,
            remote,
            local_socket_id,
            initial_seq,
            opts,
            Timebase::new(now),
        )
    }

    /// [`Connection::connect`] with an explicit [`Timebase`]. Lets tests
    /// place the timebase start close to the 32-bit µs timestamp wrap.
    pub fn connect_with_timebase(
        now: Instant,
        remote: SocketAddrV4,
        local_socket_id: SocketId,
        initial_seq: SeqNumber,
        opts: SrtOptions,
        timebase: Timebase,
    ) -> Connection {
        let hs = CallerHandshake::new(now, remote, local_socket_id, initial_seq, timebase, &opts);
        Connection {
            state: State::Connecting {
                hs,
                pending_send: VecDeque::new(),
                early_data: VecDeque::new(),
            },
            remote,
            local_socket_id,
            peer_socket_id: SocketId::HANDSHAKE,
            timebase,
            streamid: opts.streamid.clone(),
            opts,
            hs_reply: None,
            transmit_q: VecDeque::new(),
            last_sent: now,
            last_recv: now,
            last_data: now,
            exp_count: 1,
            closed_stats: Stats::default(),
        }
    }

    /// Creates an established connection on the listener side from a
    /// completed handshake. `hs_reply` is the CONCLUSION response that
    /// accepted the peer: it is queued for transmission and replayed if the
    /// peer repeats its CONCLUSION.
    pub fn accepted(
        now: Instant,
        negotiated: Negotiated,
        hs_reply: Packet,
        opts: SrtOptions,
    ) -> Connection {
        Self::accepted_with_timebase(now, negotiated, hs_reply, opts, Timebase::new(now))
    }

    /// [`Connection::accepted`] with an explicit [`Timebase`] (tests: place
    /// the timebase start close to the 32-bit µs timestamp wrap).
    pub fn accepted_with_timebase(
        now: Instant,
        negotiated: Negotiated,
        hs_reply: Packet,
        opts: SrtOptions,
        timebase: Timebase,
    ) -> Connection {
        let (sender, receiver) = transmission_pair(now, &negotiated, &opts, timebase);
        debug!(
            remote = %negotiated.remote,
            local = ?negotiated.local_socket_id,
            peer = ?negotiated.peer_socket_id,
            secured = negotiated.crypto.is_some(),
            "connection accepted (listener)"
        );
        Connection {
            remote: negotiated.remote,
            local_socket_id: negotiated.local_socket_id,
            peer_socket_id: negotiated.peer_socket_id,
            timebase,
            streamid: negotiated.streamid.clone(),
            state: State::Established {
                sender,
                receiver,
                crypto: negotiated.crypto,
            },
            opts,
            hs_reply: Some(hs_reply.clone()),
            transmit_q: VecDeque::from([hs_reply]),
            last_sent: now,
            last_recv: now,
            last_data: now,
            exp_count: 1,
            closed_stats: Stats::default(),
        }
    }

    /// Seeds the receiver's TSBPD anchor from the peer's CONCLUSION
    /// handshake — its arrival instant and header timestamp ride the same
    /// peer clock as the data packets (transmission.md §9.2). Set-once;
    /// no-op unless established. Listener runtimes call this right after
    /// [`Connection::accepted`]; the caller path is wired internally.
    pub fn set_hs_anchor(&mut self, instant: Instant, ts: Timestamp) {
        if let State::Established { receiver, .. } = &mut self.state {
            receiver.set_hs_anchor(instant, ts);
        }
    }

    /// Feeds one raw UDP datagram payload.
    pub fn handle_datagram(&mut self, now: Instant, datagram: &[u8]) {
        match Packet::parse(datagram) {
            Ok(packet) => self.handle_packet(now, packet),
            Err(PacketError::UnknownControlType(t)) => {
                // Ignored, but still counts as peer activity: libsrt resets
                // EXPCount before dispatching on the type (docs/spec/NOTES.md).
                debug!(control_type = t, "unknown control type ignored");
                self.touch(now);
            }
            Err(e) => warn!(%e, len = datagram.len(), "undecodable datagram dropped"),
        }
    }

    /// Feeds one already-parsed packet.
    pub fn handle_packet(&mut self, now: Instant, packet: Packet) {
        if matches!(self.state, State::Closed { .. }) {
            trace!("packet ignored on closed connection");
            return;
        }
        let dst = packet.dst_socket_id();
        if dst != SocketId::HANDSHAKE && dst != self.local_socket_id {
            warn!(
                dst = dst.0,
                local = self.local_socket_id.0,
                "packet for another socket dropped"
            );
            return;
        }
        // Any packet from the peer refreshes liveness (transmission.md §10).
        self.touch(now);
        match packet {
            Packet::Data(data) => self.handle_data_packet(now, data),
            Packet::Control(ctrl) => self.handle_control_packet(now, ctrl),
        }
    }

    /// Runs every timer that is due at `now`.
    pub fn handle_timer(&mut self, now: Instant) {
        let mut peer_idle = false;
        let mut data_idle = false;
        match &mut self.state {
            State::Connecting { hs, .. } => {
                if hs.is_timed_out(now) {
                    warn!("connect timeout");
                    self.close_with(now, CloseReason::ConnectTimeout, false);
                }
                return;
            }
            State::Established {
                sender, receiver, ..
            } => {
                sender.on_timer(now);
                receiver.on_timer(now);

                // EXP escalation + peer-idle break (transmission.md §10).
                let (rtt, rtt_var) = receiver.rtt();
                if now >= exp_deadline(self.last_recv, self.exp_count, rtt, rtt_var) {
                    if self.exp_count > EXP_MAX_COUNT
                        && now.duration_since(self.last_recv) >= self.opts.peer_idle_timeout
                    {
                        peer_idle = true;
                    } else {
                        self.exp_count += 1;
                        trace!(exp_count = self.exp_count, "EXP timer expired");
                    }
                }

                // Data-idle break: a plain wall-clock window on data arrival.
                // Not gated by the EXP escalation above - control traffic
                // keeps resetting EXPCount, so an escalation gate would never
                // open while the peer sends keepalives, which is exactly the
                // case this timer exists for.
                if let Some(window) = self.opts.data_idle_timeout {
                    if now.duration_since(self.last_data) >= window {
                        data_idle = true;
                    }
                }

                // Keepalive after 1 s of send silence. `last_sent` advances
                // at queue time so a late-polled driver queues only one.
                if !peer_idle
                    && !data_idle
                    && now.duration_since(self.last_sent) >= KEEPALIVE_INTERVAL
                {
                    trace!("send direction idle; queueing KEEPALIVE");
                    self.transmit_q.push_back(control(ControlType::KeepAlive));
                    self.last_sent = now;
                }
            }
            State::Closed { .. } => return,
        }
        if peer_idle {
            warn!(
                idle = ?now.duration_since(self.last_recv),
                "nothing received within the peer idle timeout; breaking connection"
            );
            self.close_with(now, CloseReason::PeerIdle, true);
        }
        // Total silence can trip both idle timers in one tick; peer idle is
        // the more precise diagnosis then, so data idle closes (and logs)
        // only when it fires alone.
        if data_idle && !peer_idle {
            warn!(
                idle = ?now.duration_since(self.last_data),
                "no data received within the data idle timeout; breaking connection"
            );
            self.close_with(now, CloseReason::DataIdle, true);
        }
    }

    /// Queues one application message for sending.
    ///
    /// Errors: [`SrtError::PayloadTooLarge`], [`SrtError::Closed`], or a
    /// queue-while-connecting (allowed: buffered until established).
    pub fn send(&mut self, now: Instant, payload: Vec<u8>) -> Result<(), SrtError> {
        match &mut self.state {
            State::Connecting { pending_send, .. } => {
                if payload.len() > self.opts.max_payload() {
                    return Err(SrtError::PayloadTooLarge(payload.len()));
                }
                if pending_send.len() >= self.opts.send_buffer_pkts {
                    // Live semantics: the oldest data is the most perishable.
                    warn!("pre-establishment send buffer full; oldest payload dropped");
                    pending_send.pop_front();
                }
                trace!(len = payload.len(), "payload buffered while connecting");
                pending_send.push_back(payload);
                Ok(())
            }
            // With crypto, the payload is encrypted in place at buffering
            // time and the KK bits are stored with it — the buffer holds
            // ciphertext, retransmissions included (encryption.md §9.3).
            State::Established { sender, crypto, .. } => {
                sender.push(now, payload, crypto.as_mut())
            }
            State::Closed { reason, .. } => Err(SrtError::Closed(*reason)),
        }
    }

    /// Starts a graceful local close (sends SHUTDOWN).
    pub fn close(&mut self, now: Instant) {
        if matches!(self.state, State::Closed { .. }) {
            return;
        }
        // SHUTDOWN is meaningful only once the peer knows us; a caller
        // abandoning a handshake just stops transmitting (handshake.md §8).
        let send_shutdown = matches!(self.state, State::Established { .. });
        debug!("local close");
        self.close_with(now, CloseReason::Local, send_shutdown);
    }

    /// Next packet to put on the wire.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Packet> {
        let packet = self.next_transmit(now)?;
        self.last_sent = now;
        let packet = match packet {
            Packet::Control(mut c) => {
                // Every (re)transmission carries a fresh timestamp; the dst
                // is the peer id (0 while it is unknown — handshake phase).
                c.timestamp = self.timebase.timestamp(now);
                c.dst_socket_id = if matches!(c.control_type, ControlType::Handshake(_))
                    && !matches!(self.state, State::Established { .. } | State::Closed { .. })
                {
                    // Caller handshake requests go to dst 0 (NOTES.md).
                    SocketId::HANDSHAKE
                } else {
                    self.peer_socket_id
                };
                Packet::Control(c)
            }
            Packet::Data(mut d) => {
                // Data keeps the origin timestamp stamped by the sender —
                // restamping retransmissions breaks peer TSBPD (NOTES.md).
                d.dst_socket_id = self.peer_socket_id;
                Packet::Data(d)
            }
        };
        trace!(dst = packet.dst_socket_id().0, "transmit");
        Some(packet)
    }

    /// Next in-order payload released by TSBPD.
    pub fn poll_deliver(&mut self, now: Instant) -> Option<Vec<u8>> {
        match &mut self.state {
            State::Established { receiver, .. } => receiver.poll_deliver(now),
            // Data received before a close may still drain (§11).
            State::Closed {
                receiver: Some(receiver),
                ..
            } => receiver.poll_deliver(now),
            _ => None,
        }
    }

    /// Earliest instant `handle_timer` must run.
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if !self.transmit_q.is_empty() {
            // Packets are waiting; the driver should drain immediately.
            return Some(now);
        }
        match &self.state {
            State::Connecting { hs, .. } => hs.next_deadline(),
            State::Established {
                sender, receiver, ..
            } => {
                let mut deadline = receiver
                    .next_deadline(now)
                    .unwrap_or(now + KEEPALIVE_INTERVAL);
                if let Some(t) = sender.next_deadline() {
                    deadline = deadline.min(t);
                }
                deadline = deadline.min(self.last_sent + KEEPALIVE_INTERVAL);
                let (rtt, rtt_var) = receiver.rtt();
                deadline = deadline.min(exp_deadline(self.last_recv, self.exp_count, rtt, rtt_var));
                if let Some(window) = self.opts.data_idle_timeout {
                    deadline = deadline.min(self.last_data + window);
                }
                Some(deadline)
            }
            // A closed connection drives no timers; remaining receive-buffer
            // data drains through on-demand `poll_deliver` calls.
            State::Closed { .. } => None,
        }
    }

    pub fn state(&self) -> ConnState {
        match &self.state {
            State::Connecting { .. } => ConnState::Connecting,
            State::Established { .. } => ConnState::Established,
            State::Closed { reason, .. } => ConnState::Closed(*reason),
        }
    }

    pub fn remote(&self) -> SocketAddrV4 {
        self.remote
    }

    /// Peer's StreamID (listener side; callers see their own option).
    pub fn streamid(&self) -> Option<&str> {
        self.streamid.as_deref()
    }

    /// Effective per-message payload size limit for [`Connection::send`]:
    /// the locally configured cap while connecting, the negotiated sender
    /// limit (min of both sides' MSS, minus 44 bytes of headers) once
    /// established.
    pub fn max_payload(&self) -> usize {
        match &self.state {
            State::Established { sender, .. } => sender.max_payload(),
            _ => self.opts.max_payload(),
        }
    }

    pub fn stats(&self) -> Stats {
        match &self.state {
            State::Connecting { .. } => Stats::default(),
            State::Established {
                sender,
                receiver,
                crypto,
            } => merge_stats(sender, receiver, crypto.as_ref()),
            State::Closed { .. } => self.closed_stats,
        }
    }

    // ---- internals ----

    /// Refreshes peer liveness: any received packet counts (NOTES.md).
    fn touch(&mut self, now: Instant) {
        self.last_recv = now;
        self.exp_count = 1;
    }

    fn handle_data_packet(&mut self, now: Instant, data: DataPacket) {
        // Data arrival, decryptable or not, resets the data-idle window.
        self.last_data = now;
        let discrepancy = match &mut self.state {
            State::Connecting { early_data, .. } => {
                // Data can race ahead of the conclusion response
                // (handshake.md §5.5); buffer a little, drop the rest (NAK
                // recovery fetches it after establishment). Encrypted
                // packets are buffered too: the crypto context arrives with
                // the negotiated handshake and decrypts them at establish.
                if early_data.len() < EARLY_DATA_MAX {
                    trace!(
                        seq = data.seq.value(),
                        "early data buffered while connecting"
                    );
                    early_data.push_back((now, data));
                } else {
                    trace!(
                        seq = data.seq.value(),
                        "early-data buffer full; packet dropped"
                    );
                }
                false
            }
            State::Established {
                receiver, crypto, ..
            } => {
                ingest_data(now, receiver, crypto.as_mut(), data);
                receiver.sequence_discrepancy()
            }
            State::Closed { .. } => unreachable!("checked in handle_packet"),
        };
        if discrepancy {
            // Reception can never resume (transmission.md §7.1): break so
            // the application can reconnect instead of idling forever.
            warn!("sequence discrepancy; breaking connection");
            self.close_with(now, CloseReason::SequenceDiscrepancy, true);
        }
    }

    fn handle_control_packet(&mut self, now: Instant, ctrl: ControlPacket) {
        match ctrl.control_type {
            ControlType::Handshake(cif) => self.handle_handshake_packet(now, ctrl.timestamp, cif),
            ControlType::Shutdown => {
                debug!("peer SHUTDOWN");
                self.close_with(now, CloseReason::Shutdown, false);
            }
            ControlType::KeepAlive => trace!("keepalive"), // liveness already refreshed
            ControlType::CongestionWarning => {
                // Never sent by 1.4.4; pacing is input-driven here — ignore.
                debug!("congestion warning ignored");
            }
            ControlType::PeerError { code } => warn!(code, "PEERERROR ignored (live mode)"),
            // In-stream KM refresh KMX (docs/spec/encryption.md §11).
            ControlType::KmReq(payload) => self.handle_kmreq(&payload),
            ControlType::KmRsp(payload) => self.handle_kmrsp(&payload),
            other => self.handle_transmission_control(now, other),
        }
    }

    /// ACK / NAK / ACKACK / DROPREQ — meaningful only when established.
    fn handle_transmission_control(&mut self, now: Instant, ct: ControlType) {
        let State::Established {
            sender,
            receiver,
            crypto,
        } = &mut self.state
        else {
            trace!("transmission control packet outside established state dropped");
            return;
        };
        let mut ackack_reply = None;
        let mut violation = false;
        let mut km_req = None;
        match ct {
            ControlType::Ack { ack_number, cif } => {
                match sender.handle_ack(now, ack_number, &cif) {
                    Ok(reply) => {
                        ackack_reply = reply;
                        // Refresh decisions and KMREQ retry pacing run on
                        // the ACK-processing path only (encryption.md
                        // §10.2, §11.2); the pacing clock is the
                        // sender-side smoothed RTT.
                        if let Some(crypto) = crypto.as_mut() {
                            let (srtt_us, _) = sender.rtt();
                            km_req = crypto.on_ack(now, srtt_us);
                        }
                    }
                    Err(_) => violation = true,
                }
            }
            ControlType::Nak(ranges) => {
                sender.handle_nak(now, &ranges);
                violation = sender.protocol_violation();
            }
            ControlType::AckAck { ack_number } => receiver.handle_ackack(now, ack_number),
            ControlType::DropRequest {
                msg_number,
                first,
                last,
            } => {
                receiver.handle_dropreq(now, msg_number, first, last);
            }
            _ => unreachable!("dispatched in handle_control_packet"),
        }
        if let Some(payload) = km_req {
            // Initial/refresh KMREQ (or a paced retry) as `UMSG_EXT`
            // (encryption.md §11.1); poll_transmit stamps it like any
            // control packet. Length only — never the KM bytes.
            debug!(kmreq_len = payload.len(), "in-stream KMREQ queued");
            self.transmit_q
                .push_back(control(ControlType::KmReq(payload)));
        }
        if let Some(ack_number) = ackack_reply {
            self.transmit_q
                .push_back(control(ControlType::AckAck { ack_number }));
        }
        if violation {
            // libsrt hard-breaks on ACK/NAK for data never sent (§6/§7.4).
            warn!("peer protocol violation; breaking connection");
            self.close_with(now, CloseReason::Local, true);
        }
    }

    /// In-stream `UMSG_EXT` KMREQ (docs/spec/encryption.md §11.3): a peer
    /// key refresh, or the unsolicited fake-KM of a permissive failed-KMX
    /// responder (§6.2 step 6). Success → full-echo KMRSP. Failure policy
    /// (encryption is always enforced): NO RESPONSE AT ALL, and the
    /// connection stays up regardless — the §11.3 non-enforced 1-word
    /// status KMRSP is not implemented. An endpoint without a crypto
    /// context is equally silent (packets.md §5.10).
    fn handle_kmreq(&mut self, payload: &[u8]) {
        let State::Established { crypto, .. } = &mut self.state else {
            trace!("in-stream KMREQ ignored while not established");
            return;
        };
        let response = match crypto.as_mut() {
            Some(crypto) => match crypto.handle_kmreq(payload) {
                KmReqOutcome::Installed(echo) => {
                    debug!(kmrsp_len = echo.len(), "in-stream KM installed; echoing KMRSP");
                    Some(echo)
                }
                KmReqOutcome::Failed(state) => {
                    debug!(?state, "in-stream KMREQ failed; silent (enforced encryption)");
                    None
                }
            },
            None => {
                debug!("in-stream KMREQ without a crypto context; silent (enforced encryption)");
                None
            }
        };
        if let Some(payload) = response {
            self.transmit_q
                .push_back(control(ControlType::KmRsp(payload)));
        }
    }

    /// In-stream `UMSG_EXT` KMRSP (docs/spec/encryption.md §6.3, §11.3):
    /// feeds the engine — echo confirmation stops the KMREQ retries, a
    /// 1-word status applies the peer-failure state table. Never a
    /// connection consequence, whatever the outcome.
    fn handle_kmrsp(&mut self, payload: &[u8]) {
        let State::Established {
            crypto: Some(crypto),
            ..
        } = &mut self.state
        else {
            trace!("KMRSP ignored (no crypto context)");
            return;
        };
        let outcome = crypto.handle_kmrsp(payload);
        debug!(?outcome, "in-stream KMRSP processed");
    }

    fn handle_handshake_packet(
        &mut self,
        now: Instant,
        hs_ts: Timestamp,
        cif: crate::packet::HandshakeCif,
    ) {
        let result = match &mut self.state {
            State::Connecting { hs, .. } => hs.handle_handshake(now, &cif),
            State::Established { .. } => {
                if cif.handshake_type == HandshakeType::Conclusion {
                    match &self.hs_reply {
                        Some(reply) => {
                            // Lost response: every repeated CONCLUSION is
                            // re-answered with the same-shaped reply (§5.5).
                            debug!("repeated CONCLUSION; replaying stored handshake reply");
                            self.transmit_q.push_back(reply.clone());
                        }
                        None => {
                            trace!("late conclusion response ignored (caller established)")
                        }
                    }
                } else {
                    trace!(hs_type = ?cif.handshake_type, "handshake packet ignored when established");
                }
                return;
            }
            State::Closed { .. } => unreachable!("checked in handle_packet"),
        };
        match result {
            Ok(Some(negotiated)) => self.establish(now, hs_ts, negotiated),
            Ok(None) => {}
            Err(e) => {
                let reason = match &e {
                    SrtError::Rejected(code) => CloseReason::Rejected(*code),
                    SrtError::EncryptionUnsupported => CloseReason::Rejected(reject::UNSECURE),
                    SrtError::ConnectTimeout => CloseReason::ConnectTimeout,
                    _ => CloseReason::Local,
                };
                warn!(%e, "handshake failed");
                self.close_with(now, reason, false);
            }
        }
    }

    /// Caller side: transition Connecting → Established, flushing payloads
    /// queued by `send` and data packets that raced the response.
    ///
    /// `hs_ts` is the CONCLUSION response's header timestamp: it rides the
    /// same peer clock as the data packets, so it seeds the TSBPD anchor
    /// (transmission.md §9.2).
    fn establish(&mut self, now: Instant, hs_ts: Timestamp, negotiated: Negotiated) {
        let (sender, receiver) = transmission_pair(now, &negotiated, &self.opts, self.timebase);
        self.peer_socket_id = negotiated.peer_socket_id;
        self.streamid = negotiated.streamid.clone();
        debug!(
            peer = ?negotiated.peer_socket_id,
            secured = negotiated.crypto.is_some(),
            "connection established (caller)"
        );
        let prev = std::mem::replace(
            &mut self.state,
            State::Established {
                sender,
                receiver,
                crypto: negotiated.crypto,
            },
        );
        let State::Connecting {
            pending_send,
            early_data,
            ..
        } = prev
        else {
            unreachable!("establish is only reached from Connecting");
        };
        let State::Established {
            sender,
            receiver,
            crypto,
        } = &mut self.state
        else {
            unreachable!("state was just set");
        };
        receiver.set_hs_anchor(now, hs_ts);
        for (at, pkt) in early_data {
            // Replayed with the original arrival instant so the TSBPD
            // anchor is not skewed by the buffering delay; runs through the
            // same decrypt step as live arrivals.
            ingest_data(at, receiver, crypto.as_mut(), pkt);
        }
        for payload in pending_send {
            if let Err(e) = sender.push(now, payload, crypto.as_mut()) {
                warn!(%e, "payload buffered while connecting was dropped");
            }
        }
        self.exp_count = 1;
        self.last_recv = now;
        self.last_data = now;
    }

    fn close_with(&mut self, now: Instant, reason: CloseReason, send_shutdown: bool) {
        if matches!(self.state, State::Closed { .. }) {
            return;
        }
        debug!(%reason, "connection closed");
        self.closed_stats = self.stats();
        if send_shutdown {
            // Best effort, sent once, never retransmitted (§11).
            self.transmit_q.push_back(control(ControlType::Shutdown));
            self.last_sent = now;
        }
        let prev = std::mem::replace(
            &mut self.state,
            State::Closed {
                reason,
                receiver: None,
            },
        );
        if let (State::Established { receiver, .. }, State::Closed { receiver: slot, .. }) =
            (prev, &mut self.state)
        {
            *slot = Some(receiver);
        }
    }

    fn next_transmit(&mut self, now: Instant) -> Option<Packet> {
        if let Some(p) = self.transmit_q.pop_front() {
            return Some(p);
        }
        match &mut self.state {
            State::Connecting { hs, .. } => hs.poll_transmit(now),
            State::Established {
                sender, receiver, ..
            } => {
                // Control before data: ACKs/NAKs must not queue behind a
                // burst of payloads.
                if let Some(ct) = receiver.poll_control(now) {
                    return Some(control(ct));
                }
                if let Some(ct) = sender.poll_control() {
                    return Some(control(ct));
                }
                sender.poll_transmit(now).map(Packet::Data)
            }
            State::Closed { .. } => None,
        }
    }
}

/// Control-packet shell; timestamp and dst are stamped in `poll_transmit`.
fn control(control_type: ControlType) -> Packet {
    Packet::Control(ControlPacket {
        timestamp: Timestamp(0),
        dst_socket_id: SocketId::HANDSHAKE,
        control_type,
    })
}

/// EXP expiry `exp_count` deadlines after `last_recv`
/// (transmission.md §10): `EXPCount·(SRTT + 4·RTTVar) + 10 ms`,
/// floor `EXPCount·300 ms`.
fn exp_deadline(last_recv: Instant, exp_count: u32, rtt_us: u32, rtt_var_us: u32) -> Instant {
    let count = u64::from(exp_count.max(1));
    let period = count * (u64::from(rtt_us) + 4 * u64::from(rtt_var_us)) + EXP_PAD_US;
    last_recv + Duration::from_micros(period.max(count * EXP_MIN_INTERVAL_US))
}

/// Builds the established-state machines from a completed negotiation.
fn transmission_pair(
    now: Instant,
    negotiated: &Negotiated,
    opts: &SrtOptions,
    timebase: Timebase,
) -> (Sender, Receiver) {
    // Payload limit from the agreed MSS (min of both sides), capped by ours.
    let max_payload = opts
        .max_payload()
        .min((negotiated.mss as usize).saturating_sub(44));
    let sender = Sender::new(SenderConfig {
        initial_seq: negotiated.send_initial_seq,
        flow_window: opts.flow_window.min(negotiated.flow_window),
        snd_latency: negotiated.snd_latency,
        max_payload,
        buffer_pkts: opts.send_buffer_pkts,
        timebase,
    });
    let mut receiver = Receiver::new(
        now,
        ReceiverConfig {
            initial_seq: negotiated.recv_initial_seq,
            rcv_latency: negotiated.rcv_latency,
            buffer_pkts: opts.recv_buffer_pkts,
        },
    );
    // Periodic-NAK CIF truncation follows the negotiated payload limit.
    receiver.set_max_payload(max_payload);
    (sender, receiver)
}

/// Feeds one data packet to the receiver through the decrypt step
/// (docs/spec/encryption.md §9.4). KK = None passes through untouched —
/// cleartext is accepted even on a secured link, a rule owned by
/// [`Crypto::decrypt`]. An unkeyed SEK slot, or any KK ≠ None without a
/// crypto context (unencrypted endpoint receiving encrypted data,
/// packets.md §5.10), makes the packet undecryptable: it still occupies
/// its sequence slot and is ACKed, but is never delivered and never
/// NAK-repaired.
fn ingest_data(
    now: Instant,
    receiver: &mut Receiver,
    crypto: Option<&mut Crypto>,
    mut data: DataPacket,
) {
    let decrypted = match crypto {
        Some(crypto) => crypto
            .decrypt(data.seq, data.encryption, &mut data.payload)
            .is_ok(),
        None => data.encryption == EncryptionFlags::None,
    };
    if decrypted {
        // §9.4: the KK bits are cleared once the payload is plaintext.
        data.encryption = EncryptionFlags::None;
        receiver.handle_data(now, data);
        return;
    }
    let seq = data.seq.value();
    let kk = data.encryption;
    // Warn once — on the 0 → 1 transition of the counter, which only
    // advances when the packet occupies a buffer slot (belated/duplicate/
    // overflow arrivals do not tick it) — then trace: a key mismatch
    // (encryption.md §8 rows 4/11, or a lost refresh KMREQ) would
    // otherwise log per packet. States and lengths only — never key
    // material.
    let first = receiver.undecrypted_count() == 0;
    receiver.handle_undecryptable(now, data);
    if first && receiver.undecrypted_count() == 1 {
        warn!(seq, ?kk,
            "undecryptable data packet (no usable key for its KK slot); further ones logged at trace");
    } else {
        trace!(
            seq,
            ?kk,
            undecrypted = receiver.undecrypted_count(),
            "undecryptable data packet"
        );
    }
}

fn merge_stats(sender: &Sender, receiver: &Receiver, crypto: Option<&Crypto>) -> Stats {
    let s = sender.stats();
    let r = receiver.stats();
    Stats {
        pkts_sent: s.pkts_sent,
        pkts_recv: r.pkts_recv,
        bytes_sent: s.bytes_sent,
        bytes_recv: r.bytes_recv,
        pkts_retransmitted: s.pkts_retransmitted,
        pkts_send_dropped: s.pkts_dropped,
        pkts_recv_dropped: r.pkts_dropped,
        pkts_recv_lost: r.pkts_lost,
        undecrypted_pkts: receiver.undecrypted_count(),
        km_refreshes: crypto.map_or(0, Crypto::key_switches),
        rtt_us: r.rtt_us,
        rtt_var_us: r.rtt_var_us,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::packet::{
        AckCif,
        HandshakeCif,
        LossRange,
        MsgNumber,
        PacketPosition,
    };

    const CALLER_ID: SocketId = SocketId(0x0102_0304);
    const ACCEPT_ID: SocketId = SocketId(0x00A1_B2C3);
    const ISN: SeqNumber = SeqNumber::new(1000);
    const UNUSED_ISN: SeqNumber = SeqNumber::new(9);
    const MS: Duration = Duration::from_millis(1);

    fn caller_addr() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 50_000)
    }

    fn listener_addr() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 4200)
    }

    fn caller(now: Instant, opts: SrtOptions) -> Connection {
        Connection::connect(now, listener_addr(), CALLER_ID, ISN, opts)
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

    fn control_to(peer: SocketId, control_type: ControlType) -> Packet {
        Packet::Control(ControlPacket {
            timestamp: Timestamp(0),
            dst_socket_id: peer,
            control_type,
        })
    }

    fn data_packet(seq: u32, dst: SocketId, payload: Vec<u8>) -> DataPacket {
        DataPacket {
            seq: SeqNumber::new(seq),
            position: PacketPosition::Only,
            order: false,
            encryption: EncryptionFlags::None,
            retransmitted: false,
            msg_number: MsgNumber::new(1),
            timestamp: Timestamp(0),
            dst_socket_id: dst,
            payload,
        }
    }

    /// Runs the full in-memory handshake through the Connection API.
    /// Returns `(caller, accepted)` — both established at `t0`.
    fn establish_pair(
        t0: Instant,
        copts: SrtOptions,
        lopts: SrtOptions,
    ) -> (Connection, Connection) {
        let mut c = caller(t0, copts);
        let mut l = Listener::new(7, Timebase::new(t0), lopts.clone());

        let ind_req = c.poll_transmit(t0).expect("induction request");
        assert_eq!(ind_req.dst_socket_id(), SocketId::HANDSHAKE);
        let ind_rsp =
            match l.handle_handshake(t0, caller_addr(), hs_cif(&ind_req), ACCEPT_ID, UNUSED_ISN) {
                ListenerAction::Reply(p) => p,
                _ => panic!("expected induction reply"),
            };
        c.handle_packet(t0, ind_rsp);
        assert_eq!(c.state(), ConnState::Connecting);

        let conc_req = c.poll_transmit(t0).expect("conclusion request");
        let (reply, negotiated) =
            match l.handle_handshake(t0, caller_addr(), hs_cif(&conc_req), ACCEPT_ID, UNUSED_ISN) {
                ListenerAction::Accept { reply, negotiated } => (reply, negotiated),
                _ => panic!("expected accept"),
            };
        let accepted = Connection::accepted(t0, *negotiated, reply.clone(), lopts);
        c.handle_packet(t0, reply);
        assert_eq!(c.state(), ConnState::Established);
        assert_eq!(accepted.state(), ConnState::Established);
        (c, accepted)
    }

    /// Drains all pending transmissions.
    fn drain(conn: &mut Connection, now: Instant) -> Vec<Packet> {
        std::iter::from_fn(|| conn.poll_transmit(now)).collect()
    }

    /// Drives `conn` strictly at its advertised deadlines from `from` until
    /// `until` (or until it leaves Established), injecting a peer KEEPALIVE
    /// every 500 ms so peer-idle liveness stays fresh and only the data-idle
    /// window can break the connection. Returns the instant of the last
    /// processed event and everything transmitted along the way.
    fn pump_with_keepalives(
        conn: &mut Connection,
        dst: SocketId,
        from: Instant,
        until: Instant,
    ) -> (Instant, Vec<Packet>) {
        const KEEPALIVE_EVERY: Duration = Duration::from_millis(500);
        let mut now = from;
        let mut next_ka = from + KEEPALIVE_EVERY;
        let mut sent = Vec::new();
        while conn.state() == ConnState::Established {
            let deadline = conn
                .next_deadline(now)
                .expect("deadline while established");
            let next = deadline.min(next_ka).max(now + MS);
            if next > until {
                break;
            }
            now = next;
            if now >= next_ka {
                conn.handle_packet(now, control_to(dst, ControlType::KeepAlive));
                next_ka += KEEPALIVE_EVERY;
            }
            if now >= deadline {
                conn.handle_timer(now);
            }
            sent.extend(drain(conn, now));
            while conn.poll_deliver(now).is_some() {}
        }
        (now, sent)
    }

    #[test]
    fn sequence_discrepancy_breaks_connection() {
        let t0 = Instant::now();
        let lopts = SrtOptions {
            recv_buffer_pkts: 32,
            ..SrtOptions::default()
        };
        let (mut c, mut a) = establish_pair(t0, SrtOptions::default(), lopts);
        let _ = drain(&mut c, t0);
        let _ = drain(&mut a, t0);
        // Empty buffer + a packet beyond its entire capacity (e.g. after a
        // long outage): reception can never resume (transmission.md §7.1).
        a.handle_packet(
            t0,
            Packet::Data(data_packet(ISN.add(1000).value(), ACCEPT_ID, vec![7; 16])),
        );
        assert_eq!(
            a.state(),
            ConnState::Closed(CloseReason::SequenceDiscrepancy)
        );
        let pkts = drain(&mut a, t0);
        assert!(pkts.iter().any(|p| matches!(
            p,
            Packet::Control(ControlPacket {
                control_type: ControlType::Shutdown,
                ..
            })
        )));
    }

    #[test]
    fn tsbpd_anchor_from_handshake_not_first_data() {
        let t0 = Instant::now();
        let (mut c, mut a) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        let _ = drain(&mut a, t0);
        // Peer data stamped at its epoch start but arriving 50 ms late: with
        // the anchor seeded from the CONCLUSION response (§9.2) the delivery
        // deadline is t0 + latency, unaffected by the arrival delay. The old
        // first-data anchor would have pushed it to t0 + 50 ms + latency.
        a.send(t0, b"payload".to_vec()).unwrap();
        let data = drain(&mut a, t0)
            .into_iter()
            .find_map(|p| match p {
                Packet::Data(d) => Some(d),
                _ => None,
            })
            .expect("data packet");
        c.handle_packet(t0 + Duration::from_millis(50), Packet::Data(data));
        let latency = Duration::from_millis(120);
        assert!(c
            .poll_deliver(t0 + latency - Duration::from_millis(5))
            .is_none());
        assert_eq!(
            c.poll_deliver(t0 + latency + Duration::from_millis(5))
                .as_deref(),
            Some(&b"payload"[..]),
        );
    }

    #[test]
    fn connect_queues_induction_immediately() {
        let t0 = Instant::now();
        let mut c = caller(t0, SrtOptions::default());
        assert_eq!(c.state(), ConnState::Connecting);
        assert_eq!(c.remote(), listener_addr());
        let pkt = c.poll_transmit(t0).expect("induction request");
        assert_eq!(hs_cif(&pkt).handshake_type, HandshakeType::Induction);
        assert_eq!(pkt.dst_socket_id(), SocketId::HANDSHAKE);
        assert!(c.poll_transmit(t0).is_none());
        // Retransmit deadline drives the timer.
        assert_eq!(c.next_deadline(t0), Some(t0 + Duration::from_millis(250)));
    }

    #[test]
    fn handshake_establishes_and_peer_id_is_stamped() {
        let t0 = Instant::now();
        let (mut c, mut a) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        // The accepted connection has the conclusion reply queued.
        let pkts = drain(&mut a, t0);
        assert_eq!(pkts.len(), 1);
        assert_eq!(hs_cif(&pkts[0]).handshake_type, HandshakeType::Conclusion);
        assert_eq!(pkts[0].dst_socket_id(), CALLER_ID);

        // Outgoing data is stamped with the peer socket id.
        c.send(t0, b"hello".to_vec()).unwrap();
        let pkts = drain(&mut c, t0);
        assert_eq!(pkts.len(), 1);
        match &pkts[0] {
            Packet::Data(d) => {
                assert_eq!(d.dst_socket_id, ACCEPT_ID);
                assert_eq!(d.seq, ISN);
                assert_eq!(d.payload, b"hello");
            }
            other => panic!("expected data, got {other:?}"),
        }
    }

    #[test]
    fn send_while_connecting_buffers_until_established() {
        let t0 = Instant::now();
        let mut c = caller(t0, SrtOptions::default());
        c.send(t0, b"early-1".to_vec()).unwrap();
        c.send(t0, b"early-2".to_vec()).unwrap();
        // Oversized payloads are rejected even while connecting.
        assert!(matches!(
            c.send(t0, vec![0; 1457]),
            Err(SrtError::PayloadTooLarge(1457))
        ));
        assert!(c.poll_transmit(t0).is_some()); // the induction request
        assert!(c.poll_transmit(t0).is_none()); // no data yet

        // Complete the handshake; the buffered payloads flush in order.
        let mut l = Listener::new(7, Timebase::new(t0), SrtOptions::default());
        let ind = {
            let mut c2 = caller(t0, SrtOptions::default());
            c2.poll_transmit(t0).unwrap()
        };
        let rsp = match l.handle_handshake(t0, caller_addr(), hs_cif(&ind), ACCEPT_ID, UNUSED_ISN) {
            ListenerAction::Reply(p) => p,
            _ => panic!(),
        };
        c.handle_packet(t0, rsp);
        let conc = c.poll_transmit(t0).unwrap();
        let reply =
            match l.handle_handshake(t0, caller_addr(), hs_cif(&conc), ACCEPT_ID, UNUSED_ISN) {
                ListenerAction::Accept { reply, .. } => reply,
                _ => panic!(),
            };
        c.handle_packet(t0, reply);
        assert_eq!(c.state(), ConnState::Established);
        let payloads: Vec<Vec<u8>> = drain(&mut c, t0)
            .into_iter()
            .filter_map(|p| match p {
                Packet::Data(d) => Some(d.payload),
                _ => None,
            })
            .collect();
        assert_eq!(payloads, vec![b"early-1".to_vec(), b"early-2".to_vec()]);
    }

    #[test]
    fn early_data_is_buffered_and_fed_to_receiver() {
        let t0 = Instant::now();
        let mut c = caller(t0, SrtOptions::default());
        let mut l = Listener::new(7, Timebase::new(t0), SrtOptions::default());
        let ind = c.poll_transmit(t0).unwrap();
        let rsp = match l.handle_handshake(t0, caller_addr(), hs_cif(&ind), ACCEPT_ID, UNUSED_ISN) {
            ListenerAction::Reply(p) => p,
            _ => panic!(),
        };
        c.handle_packet(t0, rsp);
        let conc = c.poll_transmit(t0).unwrap();
        let reply =
            match l.handle_handshake(t0, caller_addr(), hs_cif(&conc), ACCEPT_ID, UNUSED_ISN) {
                ListenerAction::Accept { reply, .. } => reply,
                _ => panic!(),
            };

        // Data arrives BEFORE the conclusion response (lost/reordered).
        let t1 = t0 + MS;
        c.handle_packet(
            t1,
            Packet::Data(data_packet(ISN.value(), CALLER_ID, vec![42; 8])),
        );
        assert_eq!(c.state(), ConnState::Connecting);
        assert!(c.poll_deliver(t1 + Duration::from_secs(1)).is_none());

        let t2 = t0 + MS * 2;
        c.handle_packet(t2, reply);
        assert_eq!(c.state(), ConnState::Established);
        // TSBPD releases the early packet at its arrival + latency (120 ms).
        assert!(c.poll_deliver(t1 + Duration::from_millis(119)).is_none());
        assert_eq!(
            c.poll_deliver(t1 + Duration::from_millis(121)),
            Some(vec![42; 8])
        );
    }

    #[test]
    fn duplicate_conclusion_replays_stored_reply() {
        let t0 = Instant::now();
        let mut c = caller(t0, SrtOptions::default());
        let mut l = Listener::new(7, Timebase::new(t0), SrtOptions::default());
        let ind = c.poll_transmit(t0).unwrap();
        let rsp = match l.handle_handshake(t0, caller_addr(), hs_cif(&ind), ACCEPT_ID, UNUSED_ISN) {
            ListenerAction::Reply(p) => p,
            _ => panic!(),
        };
        c.handle_packet(t0, rsp);
        let conc = c.poll_transmit(t0).unwrap();
        let (reply, negotiated) =
            match l.handle_handshake(t0, caller_addr(), hs_cif(&conc), ACCEPT_ID, UNUSED_ISN) {
                ListenerAction::Accept { reply, negotiated } => (reply, negotiated),
                _ => panic!(),
            };
        let mut a = Connection::accepted(t0, *negotiated, reply, SrtOptions::default());
        let first = drain(&mut a, t0);
        assert_eq!(first.len(), 1, "initial reply queued");

        // The reply was lost: the caller retransmits its CONCLUSION.
        let t1 = t0 + Duration::from_millis(250);
        let retrans = c.poll_transmit(t1).expect("caller retransmits conclusion");
        assert_eq!(hs_cif(&retrans).handshake_type, HandshakeType::Conclusion);
        a.handle_packet(t1, retrans);
        let replay = drain(&mut a, t1);
        assert_eq!(replay.len(), 1);
        assert_eq!(hs_cif(&replay[0]), hs_cif(&first[0]));
        // Fresh timestamp on the replay is allowed; establishment works.
        c.handle_packet(t1, replay[0].clone());
        assert_eq!(c.state(), ConnState::Established);
    }

    #[test]
    fn keepalive_after_one_second_send_idle() {
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        // Just before the interval: ACK timers fire, but no keepalive.
        let t1 = t0 + Duration::from_millis(999);
        c.handle_timer(t1);
        assert!(drain(&mut c, t1).iter().all(|p| !matches!(
            p,
            Packet::Control(ControlPacket {
                control_type: ControlType::KeepAlive,
                ..
            })
        )));
        let t2 = t0 + Duration::from_millis(1001);
        assert!(c.next_deadline(t2).unwrap() <= t2);
        c.handle_timer(t2);
        let pkts = drain(&mut c, t2);
        assert!(
            pkts.iter().any(|p| matches!(
                p,
                Packet::Control(ControlPacket {
                    control_type: ControlType::KeepAlive,
                    ..
                })
            )),
            "expected a KEEPALIVE, got {pkts:?}"
        );
        // Sending the keepalive reset the idle timer: nothing more due now.
        c.handle_timer(t2);
        assert!(drain(&mut c, t2).iter().all(|p| !matches!(
            p,
            Packet::Control(ControlPacket {
                control_type: ControlType::KeepAlive,
                ..
            })
        )));
    }

    #[test]
    fn peer_idle_timeout_closes_connection() {
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        // Drive the timers exactly at the advertised deadlines.
        let mut now = t0;
        let deadline = t0 + Duration::from_secs(8);
        while c.state() == ConnState::Established && now < deadline {
            now = c
                .next_deadline(now)
                .expect("deadline while established")
                .max(now + MS);
            c.handle_timer(now);
            drain(&mut c, now);
        }
        assert_eq!(c.state(), ConnState::Closed(CloseReason::PeerIdle));
        // Default 5 s timeout with the 300 ms EXP floor: breaks at ~5.1 s.
        let idle = now.duration_since(t0);
        assert!(idle >= Duration::from_secs(5), "broke too early: {idle:?}");
        assert!(idle < Duration::from_secs(6), "broke too late: {idle:?}");
    }

    #[test]
    fn any_packet_refreshes_liveness_including_unknown_control() {
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        // An unknown control type (0x7FFF user-defined) as a raw datagram.
        let mut unknown = vec![0xFF, 0xFF, 0x00, 0x00];
        unknown.extend_from_slice(&[0; 12]);
        let mut now = t0;
        for _ in 0 .. 3 {
            // Every 4 s: a keepalive from the peer, then an unknown packet.
            now += Duration::from_secs(4);
            c.handle_datagram(now, &unknown);
            let mut t = now;
            while let Some(d) = c.next_deadline(t) {
                if d > now + Duration::from_secs(4) {
                    break;
                }
                t = d.max(t + MS);
                c.handle_timer(t);
                drain(&mut c, t);
            }
        }
        assert_eq!(
            c.state(),
            ConnState::Established,
            "liveness must be refreshed"
        );
    }

    #[test]
    fn data_idle_fires_despite_keepalives() {
        let t0 = Instant::now();
        let lopts = SrtOptions::default().data_idle_timeout(Duration::from_secs(2));
        let (_c, mut a) = establish_pair(t0, SrtOptions::default(), lopts);
        drain(&mut a, t0);
        // Keepalives every 500 ms refresh peer-idle liveness but never the
        // data-idle window: the accepted side must still break at 2 s.
        let (now, sent) = pump_with_keepalives(&mut a, ACCEPT_ID, t0, t0 + Duration::from_secs(4));
        assert_eq!(a.state(), ConnState::Closed(CloseReason::DataIdle));
        let idle = now.duration_since(t0);
        assert!(idle >= Duration::from_secs(2), "broke too early: {idle:?}");
        assert!(
            idle < Duration::from_millis(2_500),
            "broke too late: {idle:?}"
        );
        // The still-reachable peer is told with a best-effort SHUTDOWN.
        assert!(sent.iter().any(|p| matches!(
            p,
            Packet::Control(ControlPacket {
                control_type: ControlType::Shutdown,
                ..
            })
        )));
    }

    #[test]
    fn data_packet_resets_data_idle_window() {
        let t0 = Instant::now();
        let copts = SrtOptions::default().data_idle_timeout(Duration::from_secs(2));
        let (mut c, _a) = establish_pair(t0, copts, SrtOptions::default());
        drain(&mut c, t0);
        // A data packet at 1.5 s restarts the window: the connection must
        // survive past the original 2 s deadline...
        let (data_at, _) =
            pump_with_keepalives(&mut c, CALLER_ID, t0, t0 + Duration::from_millis(1_500));
        assert_eq!(c.state(), ConnState::Established);
        c.handle_packet(
            data_at,
            Packet::Data(data_packet(ISN.value(), CALLER_ID, vec![7; 16])),
        );
        let (now, _) = pump_with_keepalives(&mut c, CALLER_ID, data_at, t0 + Duration::from_secs(3));
        assert_eq!(
            c.state(),
            ConnState::Established,
            "window must reset on data arrival"
        );
        // ...and break one full window after the last data packet.
        let (end, _) = pump_with_keepalives(&mut c, CALLER_ID, now, t0 + Duration::from_secs(4));
        assert_eq!(c.state(), ConnState::Closed(CloseReason::DataIdle));
        let idle = end.duration_since(data_at);
        assert!(idle >= Duration::from_secs(2), "broke too early: {idle:?}");
        assert!(
            idle < Duration::from_millis(2_500),
            "broke too late: {idle:?}"
        );
    }

    #[test]
    fn data_idle_none_never_fires() {
        // Default options (no data-idle window): a connected but silent peer
        // that keeps sending keepalives stays connected indefinitely.
        let t0 = Instant::now();
        let (mut c, _a) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        pump_with_keepalives(&mut c, CALLER_ID, t0, t0 + Duration::from_secs(12));
        assert_eq!(c.state(), ConnState::Established);
    }

    #[test]
    fn data_idle_shorter_than_peer_idle_wins() {
        // Total silence with a 1 s data-idle window and the default 5 s
        // peer-idle timeout: the data-idle break is a plain wall-clock
        // window, not gated by the EXP escalation that guards peer-idle.
        let t0 = Instant::now();
        let copts = SrtOptions::default().data_idle_timeout(Duration::from_secs(1));
        let (mut c, _a) = establish_pair(t0, copts, SrtOptions::default());
        drain(&mut c, t0);
        let mut now = t0;
        let cap = t0 + Duration::from_secs(3);
        while c.state() == ConnState::Established && now < cap {
            now = c
                .next_deadline(now)
                .expect("deadline while established")
                .max(now + MS);
            c.handle_timer(now);
            drain(&mut c, now);
        }
        assert_eq!(c.state(), ConnState::Closed(CloseReason::DataIdle));
        let idle = now.duration_since(t0);
        assert!(idle >= Duration::from_secs(1), "broke too early: {idle:?}");
        assert!(
            idle < Duration::from_millis(1_100),
            "broke too late: {idle:?}"
        );
    }

    #[test]
    fn peer_idle_fires_first_when_shorter() {
        // Total silence trips both idle timers eventually; with the default
        // 5 s peer-idle timeout due first, the close (and its reason) is
        // PeerIdle - a 10 s data-idle window never preempts it.
        let t0 = Instant::now();
        let copts = SrtOptions::default().data_idle_timeout(Duration::from_secs(10));
        let (mut c, _a) = establish_pair(t0, copts, SrtOptions::default());
        drain(&mut c, t0);
        let mut now = t0;
        let cap = t0 + Duration::from_secs(12);
        while c.state() == ConnState::Established && now < cap {
            now = c
                .next_deadline(now)
                .expect("deadline while established")
                .max(now + MS);
            c.handle_timer(now);
            drain(&mut c, now);
        }
        assert_eq!(c.state(), ConnState::Closed(CloseReason::PeerIdle));
        let idle = now.duration_since(t0);
        assert!(idle >= Duration::from_secs(5), "broke too early: {idle:?}");
        assert!(idle < Duration::from_secs(6), "broke too late: {idle:?}");
    }

    #[test]
    fn data_idle_window_starts_at_establishment() {
        // The conclusion response is delayed 2 s (inside the 3 s connect
        // timeout): the 1 s data-idle window must start at establishment,
        // not at connection construction.
        let t0 = Instant::now();
        let mut c = caller(
            t0,
            SrtOptions::default().data_idle_timeout(Duration::from_secs(1)),
        );
        let mut l = Listener::new(7, Timebase::new(t0), SrtOptions::default());
        let ind = c.poll_transmit(t0).unwrap();
        let rsp = match l.handle_handshake(t0, caller_addr(), hs_cif(&ind), ACCEPT_ID, UNUSED_ISN) {
            ListenerAction::Reply(p) => p,
            _ => panic!(),
        };
        c.handle_packet(t0, rsp);
        let conc = c.poll_transmit(t0).unwrap();
        let reply =
            match l.handle_handshake(t0, caller_addr(), hs_cif(&conc), ACCEPT_ID, UNUSED_ISN) {
                ListenerAction::Accept { reply, .. } => reply,
                _ => panic!(),
            };
        let established_at = t0 + Duration::from_secs(2);
        c.handle_packet(established_at, reply);
        assert_eq!(c.state(), ConnState::Established);
        drain(&mut c, established_at);

        // Already 2 s past construction: a window started there would have
        // expired; one started at establishment has 1 s left.
        let (now, _) = pump_with_keepalives(
            &mut c,
            CALLER_ID,
            established_at,
            established_at + Duration::from_millis(900),
        );
        assert_eq!(
            c.state(),
            ConnState::Established,
            "window must start at establishment"
        );
        let (end, _) =
            pump_with_keepalives(&mut c, CALLER_ID, now, established_at + Duration::from_secs(2));
        assert_eq!(c.state(), ConnState::Closed(CloseReason::DataIdle));
        let idle = end.duration_since(established_at);
        assert!(idle >= Duration::from_secs(1), "broke too early: {idle:?}");
        assert!(
            idle < Duration::from_millis(1_100),
            "broke too late: {idle:?}"
        );
    }

    #[test]
    fn next_deadline_advertises_data_idle_expiry() {
        // A data-idle window shorter than every other armed timer (full-ACK
        // tick 10 ms, EXP floor 300 ms, keepalive 1 s): the advertised
        // deadline must be exactly the window expiry, so a driver with an
        // otherwise silent socket wakes right when the check is due.
        let t0 = Instant::now();
        let window = Duration::from_millis(5);
        let copts = SrtOptions::default().data_idle_timeout(window);
        let (mut c, _a) = establish_pair(t0, copts, SrtOptions::default());
        drain(&mut c, t0);
        assert_eq!(c.next_deadline(t0), Some(t0 + window));
        // Driving the timer at that instant breaks the connection.
        c.handle_timer(t0 + window);
        assert_eq!(c.state(), ConnState::Closed(CloseReason::DataIdle));
    }

    #[test]
    fn peer_shutdown_closes_without_reply() {
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        c.handle_packet(t0 + MS, control_to(CALLER_ID, ControlType::Shutdown));
        assert_eq!(c.state(), ConnState::Closed(CloseReason::Shutdown));
        // No SHUTDOWN is sent back to a peer that already shut down.
        assert!(drain(&mut c, t0 + MS).is_empty());
        assert!(matches!(
            c.send(t0 + MS, b"x".to_vec()),
            Err(SrtError::Closed(CloseReason::Shutdown))
        ));
    }

    #[test]
    fn local_close_sends_shutdown_once() {
        let t0 = Instant::now();
        let (mut c, mut a) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        c.close(t0 + MS);
        assert_eq!(c.state(), ConnState::Closed(CloseReason::Local));
        let pkts = drain(&mut c, t0 + MS);
        assert_eq!(pkts.len(), 1);
        match &pkts[0] {
            Packet::Control(p) => {
                assert_eq!(p.control_type, ControlType::Shutdown);
                assert_eq!(p.dst_socket_id, ACCEPT_ID);
            }
            other => panic!("expected SHUTDOWN, got {other:?}"),
        }
        // Second close is a no-op; nothing further is transmitted.
        c.close(t0 + MS * 2);
        assert!(drain(&mut c, t0 + MS * 2).is_empty());

        // The peer closes with reason Shutdown on receipt.
        drain(&mut a, t0);
        a.handle_packet(t0 + MS * 2, pkts[0].clone());
        assert_eq!(a.state(), ConnState::Closed(CloseReason::Shutdown));
    }

    #[test]
    fn received_data_still_drains_after_peer_shutdown() {
        let t0 = Instant::now();
        let (mut c, mut a) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        drain(&mut a, t0);
        c.send(t0, b"last words".to_vec()).unwrap();
        for p in drain(&mut c, t0) {
            a.handle_packet(t0 + MS, p);
        }
        c.close(t0 + MS);
        for p in drain(&mut c, t0 + MS) {
            a.handle_packet(t0 + MS * 2, p);
        }
        assert_eq!(a.state(), ConnState::Closed(CloseReason::Shutdown));
        // The payload is still released at its TSBPD deadline.
        let due = t0 + Duration::from_millis(125);
        assert_eq!(a.poll_deliver(due), Some(b"last words".to_vec()));
    }

    #[test]
    fn encrypted_data_without_context_is_undecryptable() {
        // encryption.md §9.4 / packets.md §5.10: KK ≠ 0 without a crypto
        // context is undecryptable by definition — the packet occupies its
        // sequence slot and is ACKed, but is never delivered; the
        // connection stays up (libsrt rcvUndecrypt).
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        let mut pkt = data_packet(ISN.value(), CALLER_ID, vec![0xEE; 4]);
        pkt.encryption = EncryptionFlags::Even;
        c.handle_packet(t0 + MS, Packet::Data(pkt));
        assert_eq!(c.state(), ConnState::Established, "drop, not break");
        assert_eq!(c.stats().undecrypted_pkts, 1);
        // Nothing is sent in reaction — in particular no SHUTDOWN.
        assert!(
            !drain(&mut c, t0 + MS).iter().any(|p| matches!(
                p,
                Packet::Control(ControlPacket {
                    control_type: ControlType::Shutdown,
                    ..
                })
            )),
            "no SHUTDOWN for an undecryptable packet"
        );

        // §9.4: the undecryptable copy occupies (and is ACKed for) its
        // slot, so a later clean copy of the same sequence is a duplicate
        // and discarded — libsrt behaves the same (the sender saw the ACK
        // and never retransmits it anyway).
        let t1 = t0 + MS * 2;
        c.handle_packet(
            t1,
            Packet::Data(data_packet(ISN.value(), CALLER_ID, vec![7; 4])),
        );
        // The next sequence delivers normally: at play time the
        // undecryptable slot is freed like a TSBPD drop and the stream
        // continues behind it.
        c.handle_packet(
            t1,
            Packet::Data(data_packet(ISN.add(1).value(), CALLER_ID, vec![8; 4])),
        );
        let due = t0 + Duration::from_millis(125);
        assert_eq!(
            c.poll_deliver(due),
            Some(vec![8; 4]),
            "stream resumes past the freed undecryptable slot"
        );
        assert!(c.poll_deliver(due).is_none());
        let stats = c.stats();
        assert_eq!(stats.undecrypted_pkts, 1);
        assert_eq!(
            stats.pkts_recv_dropped, 1,
            "the freed slot counts as a drop (libsrt folds rcvUndecrypt in)"
        );
    }

    #[test]
    fn encrypted_data_while_connecting_dropped_handshake_continues() {
        // A stray encrypted data packet racing the conclusion response must
        // not abort the handshake and must not queue a SHUTDOWN (the peer
        // id is still unknown). It is buffered like any early data and runs
        // through the decrypt step at establishment; without a negotiated
        // crypto context it lands as undecryptable (encryption.md §9.4) and
        // is never delivered.
        let t0 = Instant::now();
        let mut c = caller(t0, SrtOptions::default());
        let mut l = Listener::new(7, Timebase::new(t0), SrtOptions::default());
        let ind = c.poll_transmit(t0).unwrap();
        let rsp = match l.handle_handshake(t0, caller_addr(), hs_cif(&ind), ACCEPT_ID, UNUSED_ISN) {
            ListenerAction::Reply(p) => p,
            _ => panic!(),
        };
        c.handle_packet(t0, rsp);
        let conc = c.poll_transmit(t0).unwrap();
        let reply =
            match l.handle_handshake(t0, caller_addr(), hs_cif(&conc), ACCEPT_ID, UNUSED_ISN) {
                ListenerAction::Accept { reply, .. } => reply,
                _ => panic!(),
            };

        let t1 = t0 + MS;
        let mut pkt = data_packet(ISN.value(), CALLER_ID, vec![0xEE; 8]);
        pkt.encryption = EncryptionFlags::Both;
        c.handle_packet(t1, Packet::Data(pkt));
        assert_eq!(c.state(), ConnState::Connecting, "handshake must survive");
        assert!(
            !drain(&mut c, t1).iter().any(|p| matches!(
                p,
                Packet::Control(ControlPacket {
                    control_type: ControlType::Shutdown,
                    ..
                })
            )),
            "no SHUTDOWN queued while connecting"
        );

        // The handshake completes; the replayed early packet is counted as
        // undecryptable and nothing is ever delivered.
        let t2 = t0 + MS * 2;
        c.handle_packet(t2, reply);
        assert_eq!(c.state(), ConnState::Established);
        assert_eq!(c.stats().undecrypted_pkts, 1);
        assert!(c.poll_deliver(t2 + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn ack_for_unsent_data_breaks_connection() {
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        let ack = ControlType::Ack {
            ack_number: 1,
            cif: AckCif {
                last_ack_seq: ISN.add(100), // nothing was ever sent
                rtt_us: Some(100_000),
                rtt_var_us: Some(50_000),
                avail_buf_pkts: Some(8192),
                recv_rate_pkts: Some(0),
                link_capacity_pkts: Some(0),
                recv_rate_bytes: Some(0),
            },
        };
        c.handle_packet(t0 + MS, control_to(CALLER_ID, ack));
        assert_eq!(c.state(), ConnState::Closed(CloseReason::Local));
    }

    #[test]
    fn nak_for_unsent_data_breaks_connection() {
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        let nak = ControlType::Nak(vec![LossRange {
            first: ISN,
            last: ISN.add(5),
        }]);
        c.handle_packet(t0 + MS, control_to(CALLER_ID, nak));
        assert_eq!(c.state(), ConnState::Closed(CloseReason::Local));
    }

    #[test]
    fn full_ack_gets_ackack_reply() {
        let t0 = Instant::now();
        let (mut c, mut a) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        drain(&mut a, t0);
        c.send(t0, vec![1; 10]).unwrap();
        for p in drain(&mut c, t0) {
            a.handle_packet(t0 + MS, p);
        }
        // The receiver's 10 ms ACK tick.
        let t_ack = t0 + Duration::from_millis(11);
        a.handle_timer(t_ack);
        let acks = drain(&mut a, t_ack);
        assert!(acks.iter().any(|p| matches!(
            p,
            Packet::Control(ControlPacket {
                control_type: ControlType::Ack { ack_number: 1, .. },
                ..
            })
        )));
        for p in acks {
            c.handle_packet(t_ack + MS, p);
        }
        let replies = drain(&mut c, t_ack + MS);
        assert!(replies.iter().any(|p| matches!(
            p,
            Packet::Control(ControlPacket {
                control_type: ControlType::AckAck { ack_number: 1 },
                ..
            })
        )));
    }

    #[test]
    fn packets_for_other_sockets_are_dropped() {
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        let stray = data_packet(ISN.value(), SocketId(0xDEAD), vec![1; 4]);
        c.handle_packet(t0 + MS, Packet::Data(stray));
        let stats = c.stats();
        assert_eq!(
            stats.pkts_recv, 0,
            "stray packet must not reach the receiver"
        );
    }

    #[test]
    fn connect_timeout_closes() {
        let t0 = Instant::now();
        let mut c = caller(t0, SrtOptions::default());
        assert!(c.poll_transmit(t0).is_some());
        c.handle_timer(t0 + Duration::from_millis(2_999));
        assert_eq!(c.state(), ConnState::Connecting);
        c.handle_timer(t0 + Duration::from_secs(3));
        assert_eq!(c.state(), ConnState::Closed(CloseReason::ConnectTimeout));
        assert!(c.poll_transmit(t0 + Duration::from_secs(3)).is_none());
        assert_eq!(c.next_deadline(t0 + Duration::from_secs(3)), None);
    }

    #[test]
    fn handshake_rejection_closes_with_reason() {
        let t0 = Instant::now();
        let mut c = caller(t0, SrtOptions::default());
        let ind = c.poll_transmit(t0).unwrap();
        let rejection = HandshakeCif {
            handshake_type: HandshakeType::Rejection(reject::BACKLOG),
            ..hs_cif(&ind).clone()
        };
        c.handle_packet(t0, control_to(CALLER_ID, ControlType::Handshake(rejection)));
        assert_eq!(
            c.state(),
            ConnState::Closed(CloseReason::Rejected(reject::BACKLOG))
        );
    }

    #[test]
    fn stats_merge_sender_and_receiver() {
        let t0 = Instant::now();
        let (mut c, mut a) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        drain(&mut a, t0);
        c.send(t0, vec![7; 100]).unwrap();
        c.send(t0, vec![8; 100]).unwrap();
        for p in drain(&mut c, t0) {
            a.handle_packet(t0 + MS, p);
        }
        let cs = c.stats();
        assert_eq!(cs.pkts_sent, 2);
        assert_eq!(cs.bytes_sent, 200);
        assert_eq!(cs.pkts_recv, 0);
        let as_ = a.stats();
        assert_eq!(as_.pkts_recv, 2);
        assert_eq!(as_.bytes_recv, 200);
        assert_eq!(as_.rtt_us, 100_000, "initial RTT before any sample");
        // The snapshot survives close.
        a.close(t0 + MS * 2);
        assert_eq!(a.stats().pkts_recv, 2);
    }

    #[test]
    fn next_deadline_covers_keepalive_and_ack_ticks() {
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        // Immediately after establishment: the receiver's 10 ms ACK tick is
        // the earliest duty.
        let dl = c.next_deadline(t0).expect("deadline while established");
        assert_eq!(dl, t0 + Duration::from_millis(10));
        // With queued output the deadline is "now".
        c.handle_timer(t0 + Duration::from_secs(1)); // queues a keepalive
        assert_eq!(
            c.next_deadline(t0 + Duration::from_secs(1)),
            Some(t0 + Duration::from_secs(1))
        );
        drain(&mut c, t0 + Duration::from_secs(1));
    }

    #[test]
    fn transmission_control_before_establishment_is_dropped() {
        let t0 = Instant::now();
        let mut c = caller(t0, SrtOptions::default());
        let _ = c.poll_transmit(t0);
        // An ACK while connecting must not panic or change state.
        let ack = ControlType::Ack {
            ack_number: 1,
            cif: AckCif {
                last_ack_seq: ISN,
                ..AckCif::default()
            },
        };
        c.handle_packet(t0, control_to(CALLER_ID, ack));
        assert_eq!(c.state(), ConnState::Connecting);
    }

    #[test]
    fn streamid_visible_on_both_sides() {
        let t0 = Instant::now();
        let copts = SrtOptions::default().streamid("live/cam-7");
        let (c, a) = establish_pair(t0, copts, SrtOptions::default());
        assert_eq!(c.streamid(), Some("live/cam-7"));
        assert_eq!(a.streamid(), Some("live/cam-7"));
    }

    // ---- encryption wiring (docs/spec/encryption.md §§6, 9, 10, 11) ----

    const PASSPHRASE: &str = "correct horse battery";

    /// Options for an encrypted connection. `refresh` = `(rr, pa)` sets a
    /// tiny KM refresh rate / pre-announce window (encryption.md §10.1) so
    /// a whole refresh cycle fits in a short test.
    fn crypto_opts(refresh: Option<(u32, u32)>) -> SrtOptions {
        SrtOptions {
            passphrase: Some(PASSPHRASE.to_string().into()),
            km_refresh_rate: refresh.map(|(rr, _)| rr),
            km_preannounce: refresh.map(|(_, pa)| pa),
            ..SrtOptions::default()
        }
    }

    /// Cleartext for the n-th pumped packet (1-based).
    fn msg(n: u32) -> Vec<u8> {
        format!("packet {n:04}").into_bytes()
    }

    /// Drives an encrypted pair packet-by-packet with a fake clock: each
    /// round sends `msg(n)` caller → accepted, relays everything (data,
    /// ACK, ACKACK, KMREQ/KMRSP), and ticks both timer paths — so the
    /// caller's ACK-driven refresh machine (§10.2) runs every round.
    /// `drop_kmreq` simulates losing every in-stream KMREQ. Returns the KK
    /// bits of each transmitted data packet plus the relayed KM payloads.
    fn pump_encrypted(
        c: &mut Connection,
        a: &mut Connection,
        t0: Instant,
        rounds: u32,
        drop_kmreq: bool,
    ) -> (Vec<EncryptionFlags>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut flags = Vec::new();
        let mut kmreqs = Vec::new();
        let mut kmrsps = Vec::new();
        let mut now = t0;
        for n in 1 ..= rounds {
            now += Duration::from_millis(12);
            c.send(now, msg(n)).unwrap();
            for p in drain(c, now) {
                match &p {
                    Packet::Data(d) => {
                        let n = d.seq.value() - ISN.value() + 1;
                        assert_ne!(d.payload, msg(n), "wire payload must be ciphertext");
                        flags.push(d.encryption);
                    }
                    Packet::Control(ControlPacket {
                        control_type: ControlType::KmReq(blob),
                        ..
                    }) => {
                        kmreqs.push(blob.clone());
                        if drop_kmreq {
                            continue;
                        }
                    }
                    _ => {}
                }
                a.handle_packet(now, p);
            }
            a.handle_timer(now); // 10 ms ACK tick fires every 12 ms round
            for p in drain(a, now) {
                if let Packet::Control(ControlPacket {
                    control_type: ControlType::KmRsp(blob),
                    ..
                }) = &p
                {
                    kmrsps.push(blob.clone());
                }
                c.handle_packet(now, p);
            }
            c.handle_timer(now);
        }
        (flags, kmreqs, kmrsps)
    }

    #[test]
    fn encrypted_pair_delivers_cleartext_both_directions() {
        let t0 = Instant::now();
        let (mut c, mut a) = establish_pair(t0, crypto_opts(None), crypto_opts(None));
        drain(&mut c, t0);
        drain(&mut a, t0);
        let due = t0 + Duration::from_millis(125);

        // Caller → listener: the wire carries ciphertext under the even KK
        // bits (§9.1: the first SEK of a connection is always even); the
        // application gets the cleartext back.
        let clear = b"attack at dawn".to_vec();
        c.send(t0, clear.clone()).unwrap();
        let data = drain(&mut c, t0)
            .into_iter()
            .find_map(|p| match p {
                Packet::Data(d) => Some(d),
                _ => None,
            })
            .expect("data packet");
        assert_eq!(data.encryption, EncryptionFlags::Even);
        assert_ne!(data.payload, clear, "payload must be encrypted on the wire");
        a.handle_packet(t0 + MS, Packet::Data(data));
        assert_eq!(a.poll_deliver(due), Some(clear));

        // Listener → caller: §1 — the caller's one SEK serves both
        // directions after the handshake KMX.
        let clear = b"hold position".to_vec();
        a.send(t0, clear.clone()).unwrap();
        let data = drain(&mut a, t0)
            .into_iter()
            .find_map(|p| match p {
                Packet::Data(d) => Some(d),
                _ => None,
            })
            .expect("data packet");
        assert_eq!(data.encryption, EncryptionFlags::Even);
        assert_ne!(data.payload, clear);
        c.handle_packet(t0 + MS, Packet::Data(data));
        assert_eq!(c.poll_deliver(due), Some(clear));

        assert_eq!(c.stats().undecrypted_pkts, 0);
        assert_eq!(a.stats().undecrypted_pkts, 0);
        assert_eq!(c.stats().km_refreshes, 0);
    }

    #[test]
    fn km_refresh_cycle_over_connection() {
        // §10/§11 across two Connections: with rr = 16, pa = 4 and the
        // initial counter at 1, the dual-SEK KMREQ is due on the ACK after
        // packet 12 (cnt 13 > 12) and the KK bits flip after packet 16
        // (cnt 17 > 16) — refresh decisions run only on received ACKs
        // (§10.2), which the pump provides every round.
        let t0 = Instant::now();
        let (mut c, mut a) = establish_pair(t0, crypto_opts(Some((16, 4))), crypto_opts(None));
        drain(&mut c, t0);
        drain(&mut a, t0);
        let (flags, kmreqs, kmrsps) = pump_encrypted(&mut c, &mut a, t0, 24, false);

        // Exactly one KMREQ (echo-confirmed before any 1.5×SRTT retry came
        // due): the §10.1 dual-SEK KM — 72 bytes for AES-128 (§3).
        assert_eq!(kmreqs.len(), 1, "one pre-announce KMREQ");
        assert_eq!(kmreqs[0].len(), 72, "dual-SEK KM message");
        // ...answered with the byte-exact echo KMRSP (§10.4, §6.3).
        assert!(kmrsps.iter().any(|b| b == &kmreqs[0]), "echo KMRSP relayed");

        // Packets 1..=16 ride the even key, 17.. the odd one (§10.1).
        assert_eq!(flags.len(), 24);
        for (i, kk) in flags.iter().enumerate() {
            let expect = if i < 16 {
                EncryptionFlags::Even
            } else {
                EncryptionFlags::Odd
            };
            assert_eq!(*kk, expect, "packet {}", i + 1);
        }
        assert_eq!(c.stats().km_refreshes, 1, "one completed key switch");
        assert_eq!(a.stats().km_refreshes, 0, "peer TX never switched");

        // Every payload decrypts and delivers, in order, across the switch.
        let due = t0 + Duration::from_secs(2);
        let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| a.poll_deliver(due)).collect();
        assert_eq!(delivered.len(), 24);
        for (i, p) in delivered.iter().enumerate() {
            assert_eq!(p, &msg(i as u32 + 1), "payload {}", i + 1);
        }
        assert_eq!(a.stats().undecrypted_pkts, 0);
    }

    #[test]
    fn lost_refresh_kmreq_leaves_new_key_undecryptable() {
        // §11.2 trap: the sender switches at RR whether or not the KMREQ
        // was ever answered. With every in-stream KMREQ "lost", the peer
        // never learns the odd SEK: packets 17.. arrive undecryptable —
        // ACKed, counted, never delivered — and the connection stays up.
        let t0 = Instant::now();
        let (mut c, mut a) = establish_pair(t0, crypto_opts(Some((16, 4))), crypto_opts(None));
        drain(&mut c, t0);
        drain(&mut a, t0);
        let (flags, kmreqs, kmrsps) = pump_encrypted(&mut c, &mut a, t0, 24, true);

        assert!(!kmreqs.is_empty(), "pre-announce KMREQ was emitted");
        assert!(kmrsps.is_empty(), "no KMRSP for a KMREQ never delivered");
        assert!(
            flags[16 ..].iter().all(|kk| *kk == EncryptionFlags::Odd),
            "switch happened regardless (§11.2)"
        );

        assert_eq!(c.state(), ConnState::Established);
        assert_eq!(a.state(), ConnState::Established);
        assert_eq!(
            a.stats().undecrypted_pkts,
            8,
            "every odd-key packet is undecryptable"
        );
        let due = t0 + Duration::from_secs(2);
        let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| a.poll_deliver(due)).collect();
        assert_eq!(delivered.len(), 16, "only even-key packets delivered");
    }

    #[test]
    fn endpoint_is_silent_on_bad_instream_kmreq() {
        // §11.3: a failed in-stream KMREQ gets NO response (encryption is
        // always enforced; the non-enforced 1-word status KMRSP is not
        // implemented) — and never a connection consequence. Both failure
        // classes: garbage that passes the §6.2 step-1 pre-checks but
        // fails parsing (NOSECRET class), and a truncated KM that fails
        // the pre-checks themselves (BADSECRET class).
        let t0 = Instant::now();
        for payload in [vec![0xAB; 20], vec![0; 10]] {
            let (mut c, _) = establish_pair(t0, crypto_opts(None), crypto_opts(None));
            drain(&mut c, t0);
            c.handle_packet(t0 + MS, control_to(CALLER_ID, ControlType::KmReq(payload)));
            assert_eq!(c.state(), ConnState::Established);
            assert!(
                drain(&mut c, t0 + MS).iter().all(|p| !matches!(
                    p,
                    Packet::Control(ControlPacket {
                        control_type: ControlType::KmRsp(_),
                        ..
                    })
                )),
                "a failed in-stream KMREQ is answered with silence"
            );
        }
    }

    #[test]
    fn instream_kmreq_on_unencrypted_endpoint() {
        // packets.md §5.10 / §11.3: an endpoint without a crypto context
        // is silent too (the non-enforced NOSECRET status KMRSP is not
        // implemented) — and the connection stays up.
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        c.handle_packet(
            t0 + MS,
            control_to(CALLER_ID, ControlType::KmReq(vec![0xAB; 20])),
        );
        assert_eq!(c.state(), ConnState::Established);
        assert!(drain(&mut c, t0 + MS).iter().all(|p| !matches!(
            p,
            Packet::Control(ControlPacket {
                control_type: ControlType::KmRsp(_),
                ..
            })
        )));
    }
}
