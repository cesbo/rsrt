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
        ReceiverStats,
    },
    sender::{
        Sender,
        SenderConfig,
        SenderStats,
    },
    time::{
        Timebase,
        TimestampExtender,
    },
};
use crate::{
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
/// - encrypted data packets (KK ≠ None) → drop the packet, connection stays up (packets.md §3.2:
///   without a crypto context the receiver MUST drop it; libsrt counts it in `rcvUndecrypt` and
///   discards);
/// - keepalive: send KEEPALIVE after [`KEEPALIVE_INTERVAL`] without any outgoing packet;
/// - liveness: no packet from the peer for `peer_idle_timeout` → close with
///   [`CloseReason::PeerIdle`];
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
    /// EXP expiration counter (`EXPCount`); reset to 1 by any received
    /// packet, incremented by each EXP timer expiry.
    exp_count: u32,
    /// Encrypted (KK ≠ None) data packets dropped — no crypto context here
    /// (libsrt `rcvUndecrypt` analog); also gates the warn-once log.
    undecrypted_drops: u64,
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
            exp_count: 1,
            undecrypted_drops: 0,
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
            "connection accepted (listener)"
        );
        Connection {
            state: State::Established { sender, receiver },
            remote: negotiated.remote,
            local_socket_id: negotiated.local_socket_id,
            peer_socket_id: negotiated.peer_socket_id,
            timebase,
            streamid: negotiated.streamid.clone(),
            opts,
            hs_reply: Some(hs_reply.clone()),
            transmit_q: VecDeque::from([hs_reply]),
            last_sent: now,
            last_recv: now,
            exp_count: 1,
            undecrypted_drops: 0,
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
        match &mut self.state {
            State::Connecting { hs, .. } => {
                if hs.is_timed_out(now) {
                    warn!("connect timeout");
                    self.close_with(now, CloseReason::ConnectTimeout, false);
                }
                return;
            }
            State::Established { sender, receiver } => {
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

                // Keepalive after 1 s of send silence. `last_sent` advances
                // at queue time so a late-polled driver queues only one.
                if !peer_idle && now.duration_since(self.last_sent) >= KEEPALIVE_INTERVAL {
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
            State::Established { sender, .. } => sender.push(now, payload),
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
            State::Established { sender, receiver } => {
                let mut deadline = receiver
                    .next_deadline(now)
                    .unwrap_or(now + KEEPALIVE_INTERVAL);
                if let Some(t) = sender.next_deadline() {
                    deadline = deadline.min(t);
                }
                deadline = deadline.min(self.last_sent + KEEPALIVE_INTERVAL);
                let (rtt, rtt_var) = receiver.rtt();
                deadline = deadline.min(exp_deadline(self.last_recv, self.exp_count, rtt, rtt_var));
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
            State::Established { sender, receiver } => merge_stats(sender, receiver),
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
        if data.encryption != EncryptionFlags::None {
            // No crypto context here (encryption unsupported): the packet
            // is undecryptable and MUST be dropped, never delivered
            // (docs/spec/packets.md §3.2, transmission.md §9.5) — libsrt
            // counts it in rcvUndecrypt and continues. Touching no state
            // keeps the early_data buffer clean too; the resulting sequence
            // gap recovers via NAK / TSBPD too-late drop. Warn once, then
            // trace: a misbehaving peer would otherwise log per-packet.
            self.undecrypted_drops += 1;
            if self.undecrypted_drops == 1 {
                warn!(seq = data.seq.value(), kk = ?data.encryption,
                    "encrypted data packet dropped (no crypto context); further drops logged at trace");
            } else {
                trace!(seq = data.seq.value(), kk = ?data.encryption,
                    drops = self.undecrypted_drops, "encrypted data packet dropped");
            }
            return;
        }
        let discrepancy = match &mut self.state {
            State::Connecting { early_data, .. } => {
                // Data can race ahead of the conclusion response
                // (handshake.md §5.5); buffer a little, drop the rest (NAK
                // recovery fetches it after establishment).
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
            State::Established { receiver, .. } => {
                receiver.handle_data(now, data);
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
            other => self.handle_transmission_control(now, other),
        }
    }

    /// ACK / NAK / ACKACK / DROPREQ — meaningful only when established.
    fn handle_transmission_control(&mut self, now: Instant, ct: ControlType) {
        let State::Established { sender, receiver } = &mut self.state else {
            trace!("transmission control packet outside established state dropped");
            return;
        };
        let mut ackack_reply = None;
        let mut violation = false;
        match ct {
            ControlType::Ack { ack_number, cif } => {
                match sender.handle_ack(now, ack_number, &cif) {
                    Ok(reply) => ackack_reply = reply,
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
        debug!(peer = ?negotiated.peer_socket_id, "connection established (caller)");
        let prev = std::mem::replace(&mut self.state, State::Established { sender, receiver });
        let State::Connecting {
            pending_send,
            early_data,
            ..
        } = prev
        else {
            unreachable!("establish is only reached from Connecting");
        };
        let State::Established { sender, receiver } = &mut self.state else {
            unreachable!("state was just set");
        };
        receiver.set_hs_anchor(now, hs_ts);
        for (at, pkt) in early_data {
            // Replayed with the original arrival instant so the TSBPD
            // anchor is not skewed by the buffering delay.
            receiver.handle_data(at, pkt);
        }
        for payload in pending_send {
            if let Err(e) = sender.push(now, payload) {
                warn!(%e, "payload buffered while connecting was dropped");
            }
        }
        self.exp_count = 1;
        self.last_recv = now;
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
            State::Established { sender, receiver } => {
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

fn merge_stats(sender: &Sender, receiver: &Receiver) -> Stats {
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
    fn encrypted_data_dropped_connection_survives() {
        // packets.md §3.2: no crypto context → the packet MUST be dropped,
        // never delivered; the connection stays up (libsrt rcvUndecrypt).
        let t0 = Instant::now();
        let (mut c, _) = establish_pair(t0, SrtOptions::default(), SrtOptions::default());
        drain(&mut c, t0);
        let mut pkt = data_packet(ISN.value(), CALLER_ID, vec![0xEE; 4]);
        pkt.encryption = EncryptionFlags::Even;
        c.handle_packet(t0 + MS, Packet::Data(pkt));
        assert_eq!(c.state(), ConnState::Established, "drop, not break");
        // Nothing is sent in reaction — in particular no SHUTDOWN.
        assert!(
            !drain(&mut c, t0 + MS).iter().any(|p| matches!(
                p,
                Packet::Control(ControlPacket {
                    control_type: ControlType::Shutdown,
                    ..
                })
            )),
            "no SHUTDOWN for a dropped undecryptable packet"
        );
        // The undecryptable payload is never delivered to the application.
        assert!(c.poll_deliver(t0 + Duration::from_secs(1)).is_none());

        // Corrupted-KK-bits scenario: the intact original (same seq) is
        // retransmitted and must still be accepted and delivered — the drop
        // left no trace of that sequence number in the receiver.
        let t1 = t0 + MS * 2;
        c.handle_packet(
            t1,
            Packet::Data(data_packet(ISN.value(), CALLER_ID, vec![7; 4])),
        );
        assert_eq!(c.state(), ConnState::Established);
        assert_eq!(
            c.poll_deliver(t1 + Duration::from_millis(121)),
            Some(vec![7; 4]),
            "clean retransmission of the dropped seq is delivered"
        );
    }

    #[test]
    fn encrypted_data_while_connecting_dropped_handshake_continues() {
        // A stray encrypted data packet racing the conclusion response must
        // not abort the handshake, must not queue a SHUTDOWN (the peer id is
        // still unknown), and must stay out of the early-data buffer.
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

        // The handshake completes and the encrypted payload was never
        // buffered as early data: nothing is ever delivered.
        let t2 = t0 + MS * 2;
        c.handle_packet(t2, reply);
        assert_eq!(c.state(), ConnState::Established);
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
}
