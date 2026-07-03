//! Layer 3 — listener: accepts connections, demuxes one UDP socket.
//!
//! The listener driver task owns the UDP socket (`recv_from` loop) and:
//!
//! - datagrams with destination socket id ≠ 0 are routed by local socket id to the owning
//!   connection's demux channel;
//! - handshake datagrams (destination socket id 0):
//!   - from a peer with an existing connection (matched by `(peer addr, peer socket id)`):
//!     forwarded to that connection — its `core::Connection` replays the stored CONCLUSION reply
//!     (the peer didn't see it yet);
//!   - otherwise: `core::Listener::handle_handshake` — `Reply` is sent directly; `Accept` spawns a
//!     connection driver (see `socket.rs`) plus an [`SrtSocket`] handle pushed to the accept queue;
//! - sends from all connection drivers go through the shared `Arc<tokio::net::UdpSocket>` via
//!   `send_to`;
//! - when a connection driver exits, its demux entry is cleaned up (a [`ReapGuard`] dropped by the
//!   driver notifies the reap channel).
//!
//! Backlog: if the accept queue is full, new conclusions are rejected with
//! `reject::BACKLOG`.

use std::{
    collections::HashMap,
    net::{
        SocketAddr,
        SocketAddrV4,
    },
    sync::Arc,
    time::Instant,
};

use tokio::{
    net::{
        ToSocketAddrs,
        UdpSocket,
    },
    sync::mpsc,
};
use tracing::{
    debug,
    trace,
    warn,
};

use crate::{
    core::{
        self,
        Connection,
        ListenerAction,
        Timebase,
    },
    error::{
        CloseReason,
        SrtError,
    },
    net,
    options::SrtOptions,
    packet::{
        reject,
        ControlPacket,
        ControlType,
        HandshakeCif,
        HandshakeType,
        Packet,
        SocketId,
    },
    socket::{
        spawn_connection,
        DriverIo,
        SrtSocket,
    },
};

/// Accept queue depth; conclusions arriving while it is full are rejected
/// with `reject::BACKLOG`.
const ACCEPT_BACKLOG: usize = 64;

/// Per-connection demux queue depth, datagrams. Overflow drops (live
/// semantics; ARQ recovers data loss).
const DEMUX_QUEUE: usize = 1024;

/// An SRT listener bound to a local UDP address.
///
/// Dropping the listener stops accepting new connections; established
/// sockets keep running (each has its own driver and shares the UDP socket).
pub struct SrtListener {
    accept_rx: mpsc::Receiver<(SrtSocket, SocketAddrV4)>,
    local_addr: SocketAddrV4,
}

impl SrtListener {
    /// Binds the UDP socket (IPv4) and starts the listener driver.
    ///
    /// `opts` apply to every accepted connection (`opts.streamid` is
    /// ignored; the caller supplies it).
    ///
    /// Errors: [`SrtError::InvalidPassphrase`],
    /// [`SrtError::InvalidKmParameters`], [`SrtError::NoIpv4Address`],
    /// [`SrtError::Io`].
    pub async fn bind(addr: impl ToSocketAddrs, opts: SrtOptions) -> Result<SrtListener, SrtError> {
        // Fail fast on invalid encryption options (encryption.md §2),
        // before any I/O: `core::Listener` re-derives this config and
        // would otherwise silently reject every conclusion.
        opts.crypto_config()?;
        let addr = net::resolve_v4(addr).await?;
        let udp = net::bind_udp(addr, opts.udp_recv_buffer)?;
        let local_addr = match udp.local_addr()? {
            SocketAddr::V4(a) => a,
            // The socket is AF_INET; a V6 local address cannot happen.
            SocketAddr::V6(_) => return Err(SrtError::NoIpv4Address),
        };
        let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_BACKLOG);
        let timebase = Timebase::new(Instant::now());
        let driver = ListenerDriver {
            udp: Arc::new(udp),
            core: core::Listener::new(net::random_u64(), timebase, opts.clone()),
            timebase,
            opts,
            accept_tx,
            accept_open: true,
            conns: HashMap::new(),
            by_peer: HashMap::new(),
            out: Vec::with_capacity(2048),
        };
        debug!(%local_addr, "listener bound");
        tokio::spawn(driver.run());
        Ok(SrtListener {
            accept_rx,
            local_addr,
        })
    }

    /// Waits for the next accepted connection.
    pub async fn accept(&mut self) -> Result<(SrtSocket, SocketAddrV4), SrtError> {
        // The driver outlives the handle, so a closed queue means it died.
        self.accept_rx
            .recv()
            .await
            .ok_or(SrtError::Closed(CloseReason::Local))
    }

    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local_addr
    }
}

/// Notifies the listener driver when a connection driver exits (the guard
/// is dropped at the end of the drive task), so its demux entries go away.
pub(crate) struct ReapGuard {
    tx: mpsc::UnboundedSender<SocketId>,
    id: SocketId,
}

impl Drop for ReapGuard {
    fn drop(&mut self) {
        let _ = self.tx.send(self.id);
    }
}

/// Demux entry for one accepted connection.
struct ConnEntry {
    tx: mpsc::Sender<Vec<u8>>,
    /// `(source address, peer socket id)` — the dst-0 handshake demux key.
    peer: (SocketAddrV4, SocketId),
}

struct ListenerDriver {
    udp: Arc<UdpSocket>,
    core: core::Listener,
    timebase: Timebase,
    opts: SrtOptions,
    accept_tx: mpsc::Sender<(SrtSocket, SocketAddrV4)>,
    /// False once the [`SrtListener`] handle is dropped.
    accept_open: bool,
    /// Established-traffic demux: local socket id → connection.
    conns: HashMap<SocketId, ConnEntry>,
    /// Handshake demux: (peer address, peer socket id) → local socket id.
    by_peer: HashMap<(SocketAddrV4, SocketId), SocketId>,
    /// Encode scratch buffer.
    out: Vec<u8>,
}

impl ListenerDriver {
    async fn run(mut self) {
        let (reap_tx, mut reap_rx) = mpsc::unbounded_channel();
        // Locals for the select! futures so the handlers may borrow `self`.
        let udp = Arc::clone(&self.udp);
        let accept_tx = self.accept_tx.clone();
        let mut buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                r = udp.recv_from(&mut buf) => match r {
                    Ok((n, SocketAddr::V4(from))) => {
                        self.on_datagram(from, &buf[..n], &reap_tx).await;
                    }
                    Ok((n, SocketAddr::V6(from))) => {
                        trace!(%from, len = n, "non-IPv4 datagram dropped");
                    }
                    Err(e) => debug!(%e, "listener recv error (transient)"),
                },
                // `reap_tx` lives on this stack frame: recv() never yields
                // None while the loop runs.
                Some(id) = reap_rx.recv() => self.reap(id),
                _ = accept_tx.closed(), if self.accept_open => {
                    self.accept_open = false;
                    debug!("listener handle dropped; no longer accepting");
                }
            }
            if !self.accept_open && self.conns.is_empty() {
                debug!("listener driver finished");
                return;
            }
        }
    }

    async fn on_datagram(
        &mut self,
        from: SocketAddrV4,
        datagram: &[u8],
        reap_tx: &mpsc::UnboundedSender<SocketId>,
    ) {
        if datagram.len() < 16 {
            trace!(%from, len = datagram.len(), "runt datagram dropped");
            return;
        }
        let dst = SocketId(u32::from_be_bytes([
            datagram[12],
            datagram[13],
            datagram[14],
            datagram[15],
        ]));
        if dst != SocketId::HANDSHAKE {
            // Established traffic: route by local socket id + source match.
            match self.conns.get(&dst) {
                Some(entry) if entry.peer.0 == from => {
                    match entry.tx.try_send(datagram.to_vec()) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!(dst = dst.0, "demux queue full; datagram dropped");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            // Driver already exited; the reap is in flight.
                            trace!(dst = dst.0, "connection gone; datagram dropped");
                        }
                    }
                }
                Some(_) => warn!(%from, dst = dst.0, "source address mismatch; datagram dropped"),
                None => trace!(%from, dst = dst.0, "datagram for unknown socket dropped"),
            }
            return;
        }

        // dst 0: connection-request path (NOTES.md routing rule).
        let packet = match Packet::parse(datagram) {
            Ok(p) => p,
            Err(e) => {
                debug!(%from, %e, "undecodable dst-0 datagram dropped");
                return;
            }
        };
        let Packet::Control(ControlPacket {
            timestamp: hs_ts,
            control_type: ControlType::Handshake(cif),
            ..
        }) = packet
        else {
            trace!(%from, "non-handshake dst-0 packet dropped");
            return;
        };

        // A peer we already accepted repeating its handshake means our
        // CONCLUSION reply was lost: its connection replays the stored copy.
        if let Some(local_id) = self.by_peer.get(&(from, cif.socket_id)) {
            if let Some(entry) = self.conns.get(local_id) {
                trace!(%from, "handshake for existing connection forwarded");
                let _ = entry.tx.try_send(datagram.to_vec());
            }
            return;
        }

        let now = Instant::now();
        if !self.accept_open {
            if cif.handshake_type == HandshakeType::Conclusion {
                debug!(%from, "listener closed; conclusion rejected");
                let reply = self.rejection(now, &cif, reject::CLOSE);
                self.send_packet(&reply, from).await;
            }
            return;
        }

        // Pre-roll a local socket id that is unique among live connections
        // (harmless if unused: the core consumes it only on Accept). It must
        // be picked BEFORE `handle_handshake` — the reply CIF bakes it in,
        // so regenerating afterwards would desynchronize demux and wire.
        let new_id = self.unused_socket_id(net::random_socket_id);
        match self
            .core
            .handle_handshake(now, from, &cif, new_id, net::random_isn())
        {
            ListenerAction::Reply(reply) => self.send_packet(&reply, from).await,
            ListenerAction::Drop => {}
            ListenerAction::Accept { reply, negotiated } => {
                // Reserve the accept slot BEFORE spawning anything, so a
                // full backlog costs no resources. Owned permit (from a
                // sender clone) so `self` stays borrowable below.
                let permit = match self.accept_tx.clone().try_reserve_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(%from, "accept backlog full; conclusion rejected");
                        let reply = self.rejection(now, &cif, reject::BACKLOG);
                        self.send_packet(&reply, from).await;
                        return;
                    }
                };
                let local_id = negotiated.local_socket_id;
                let peer_key = (from, negotiated.peer_socket_id);
                let (tx, rx) = mpsc::channel(DEMUX_QUEUE);
                // The accepted connection queues `reply` itself and replays
                // it on repeated CONCLUSIONs. `*negotiated` MOVES the boxed
                // value — with its crypto engine and key material — into the
                // connection (`Negotiated` is neither `Copy` nor `Clone`),
                // so the demux keys above are read out beforehand.
                let mut conn = Connection::accepted(now, *negotiated, reply, self.opts.clone());
                // TSBPD anchor from the CONCLUSION request: same peer clock
                // as the caller's data packets (transmission.md §9.2).
                conn.set_hs_anchor(now, hs_ts);
                let socket = spawn_connection(
                    conn,
                    DriverIo::Demux {
                        udp: Arc::clone(&self.udp),
                        remote: from,
                        rx,
                    },
                    &self.opts,
                    None,
                    Some(ReapGuard {
                        tx: reap_tx.clone(),
                        id: local_id,
                    }),
                );
                debug!(%from, id = local_id.0, "connection accepted");
                self.conns
                    .insert(local_id, ConnEntry { tx, peer: peer_key });
                self.by_peer.insert(peer_key, local_id);
                permit.send((socket, from));
            }
        }
    }

    /// Rolls a local socket id not used by any live connection. Without the
    /// uniqueness check a (rare, ~N_live/2^31 per accept) collision would
    /// make `conns.insert` silently evict a healthy connection's demux
    /// entry, leave its `by_peer` key permanently stale, and — both drivers
    /// holding a [`ReapGuard`] with the same id — let the evicted driver's
    /// exit reap the new connection's routing as well.
    ///
    /// `gen` is [`net::random_socket_id`] in production; injected so tests
    /// can force a collision deterministically.
    fn unused_socket_id(&self, mut gen: impl FnMut() -> SocketId) -> SocketId {
        loop {
            let id = gen();
            if !self.conns.contains_key(&id) {
                return id;
            }
        }
    }

    fn reap(&mut self, id: SocketId) {
        if let Some(entry) = self.conns.remove(&id) {
            // `unused_socket_id` keeps live ids unique, so `entry.peer`
            // always maps back to `id`; the guard is defense in depth so a
            // future invariant break can never drop another connection's
            // handshake routing.
            if self.by_peer.get(&entry.peer) == Some(&id) {
                self.by_peer.remove(&entry.peer);
            }
            debug!(id = id.0, "connection reaped");
        }
    }

    /// Rejection response, shaped like the core listener's: the received
    /// CIF echoed with the type replaced and extensions stripped, addressed
    /// to the caller's socket id.
    fn rejection(&self, now: Instant, cif: &HandshakeCif, code: u32) -> Packet {
        let mut reply = cif.clone();
        reply.handshake_type = HandshakeType::Rejection(code);
        reply.extensions = Vec::new();
        Packet::Control(ControlPacket {
            timestamp: self.timebase.timestamp(now),
            dst_socket_id: cif.socket_id,
            control_type: ControlType::Handshake(reply),
        })
    }

    async fn send_packet(&mut self, packet: &Packet, to: SocketAddrV4) {
        self.out.clear();
        packet.encode(&mut self.out);
        if let Err(e) = self.udp.send_to(&self.out, to).await {
            debug!(%to, %e, "listener send failed; datagram dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::packet::{
        HsExtension,
        SeqNumber,
        Timestamp,
    };

    fn sample_cif() -> HandshakeCif {
        HandshakeCif {
            version: 5,
            encryption: 0,
            extension_field: 0x1,
            initial_seq: SeqNumber::new(42),
            mss: 1500,
            flow_window: 8192,
            handshake_type: HandshakeType::Conclusion,
            socket_id: SocketId(0xABCD),
            cookie: 0x1234_5678,
            peer_ip: HandshakeCif::encode_peer_ip(Ipv4Addr::LOCALHOST),
            extensions: vec![HsExtension::StreamId("x".into())],
        }
    }

    /// Driver shell with a real bound socket and empty demux maps. The
    /// runtime and accept receiver are returned so they outlive the driver
    /// (`_rt` keeps the socket's reactor alive; `_accept_rx` keeps
    /// `accept_tx` open).
    fn shell_driver() -> (
        tokio::runtime::Runtime,
        ListenerDriver,
        mpsc::Receiver<(SrtSocket, SocketAddrV4)>,
    ) {
        let timebase = Timebase::new(Instant::now());
        let (accept_tx, accept_rx) = mpsc::channel(1);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let udp = rt.block_on(async {
            net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap()
        });
        let driver = ListenerDriver {
            udp: Arc::new(udp),
            core: core::Listener::new(1, timebase, SrtOptions::default()),
            timebase,
            opts: SrtOptions::default(),
            accept_tx,
            accept_open: true,
            conns: HashMap::new(),
            by_peer: HashMap::new(),
            out: Vec::new(),
        };
        (rt, driver, accept_rx)
    }

    /// Demux entry whose channel is closed; fine for map-manipulation tests
    /// that never send.
    fn conn_entry(peer: (SocketAddrV4, SocketId)) -> ConnEntry {
        let (tx, _rx) = mpsc::channel(1);
        ConnEntry { tx, peer }
    }

    fn peer_key(port: u16, id: u32) -> (SocketAddrV4, SocketId) {
        (SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), SocketId(id))
    }

    #[test]
    fn rejection_echoes_cif_and_strips_extensions() {
        let (_rt, driver, _accept_rx) = shell_driver();
        let cif = sample_cif();
        let pkt = driver.rejection(Instant::now(), &cif, reject::BACKLOG);
        let Packet::Control(ControlPacket {
            dst_socket_id,
            control_type: ControlType::Handshake(reply),
            ..
        }) = pkt
        else {
            panic!("expected handshake packet");
        };
        // Addressed to the caller's id; only type and extensions change.
        assert_eq!(dst_socket_id, cif.socket_id);
        assert_eq!(
            reply.handshake_type,
            HandshakeType::Rejection(reject::BACKLOG)
        );
        assert!(reply.extensions.is_empty());
        assert_eq!(reply.initial_seq, cif.initial_seq);
        assert_eq!(reply.cookie, cif.cookie);
        assert_eq!(reply.socket_id, cif.socket_id);
    }

    #[test]
    fn reap_guard_notifies_on_drop() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let guard = ReapGuard {
            tx,
            id: SocketId(99),
        };
        assert!(rx.try_recv().is_err());
        drop(guard);
        assert_eq!(rx.try_recv().unwrap(), SocketId(99));
    }

    /// A freshly rolled local id colliding with a live connection must be
    /// rerolled: reusing it would evict that connection's demux entry,
    /// orphan its `by_peer` key, and alias the two drivers' reap guards.
    #[test]
    fn unused_socket_id_rerolls_on_live_collision() {
        let (_rt, mut driver, _accept_rx) = shell_driver();
        driver
            .conns
            .insert(SocketId(5), conn_entry(peer_key(1000, 0xA)));

        // Free on the first roll: taken as-is.
        assert_eq!(driver.unused_socket_id(|| SocketId(9)), SocketId(9));

        // Collides twice, then lands on a free id.
        let mut rolls = [SocketId(5), SocketId(5), SocketId(7)].into_iter();
        assert_eq!(
            driver.unused_socket_id(|| rolls.next().unwrap()),
            SocketId(7)
        );
        // The live connection's entry is untouched.
        assert_eq!(driver.conns[&SocketId(5)].peer, peer_key(1000, 0xA));
    }

    #[test]
    fn reap_removes_conn_and_its_by_peer_key() {
        let (_rt, mut driver, _accept_rx) = shell_driver();
        let peer = peer_key(1000, 0xA);
        driver.conns.insert(SocketId(5), conn_entry(peer));
        driver.by_peer.insert(peer, SocketId(5));

        driver.reap(SocketId(5));
        assert!(driver.conns.is_empty());
        assert!(driver.by_peer.is_empty());

        // Reaping an unknown id is a no-op.
        driver.reap(SocketId(5));
    }

    /// Defense in depth: if a `by_peer` key ever maps to a different live
    /// connection, reaping must not tear down that connection's handshake
    /// routing.
    #[test]
    fn reap_preserves_by_peer_owned_by_another_connection() {
        let (_rt, mut driver, _accept_rx) = shell_driver();
        let peer = peer_key(1000, 0xA);
        driver.conns.insert(SocketId(5), conn_entry(peer));
        driver.by_peer.insert(peer, SocketId(6));

        driver.reap(SocketId(5));
        assert!(driver.conns.is_empty());
        assert_eq!(driver.by_peer[&peer], SocketId(6));
    }

    /// Invalid encryption options fail `bind` before any I/O: the address
    /// here cannot resolve, so reaching resolution would surface an
    /// [`SrtError::Io`] instead of the validation error.
    #[tokio::test]
    async fn bind_validates_crypto_options_before_io() {
        // Passphrase below the 10-byte minimum (encryption.md §2).
        let opts = SrtOptions::default().passphrase("short");
        let e = SrtListener::bind(("host.invalid.", 1), opts)
            .await
            .err()
            .expect("invalid passphrase must fail bind");
        assert!(matches!(e, SrtError::InvalidPassphrase), "{e:?}");

        // km_preannounce > (km_refresh_rate - 1) / 2 (encryption.md §2).
        let mut opts = SrtOptions::default().passphrase("0123456789");
        opts.km_refresh_rate = Some(10);
        opts.km_preannounce = Some(9);
        let e = SrtListener::bind(("host.invalid.", 1), opts)
            .await
            .err()
            .expect("invalid km parameters must fail bind");
        assert!(matches!(e, SrtError::InvalidKmParameters(_)), "{e:?}");
    }

    /// The wire dst-socket-id sits at bytes 12..16 of every SRT packet; the
    /// demux fast path reads it without a full parse. Keep them in sync.
    #[test]
    fn dst_socket_id_offset_matches_codec() {
        let cif = sample_cif();
        let pkt = Packet::Control(ControlPacket {
            timestamp: Timestamp(7),
            dst_socket_id: SocketId(0xDEAD_BEE5),
            control_type: ControlType::Handshake(cif),
        });
        let mut out = Vec::new();
        pkt.encode(&mut out);
        let dst = u32::from_be_bytes([out[12], out[13], out[14], out[15]]);
        assert_eq!(dst, 0xDEAD_BEE5);
    }
}
