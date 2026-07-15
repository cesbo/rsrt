//! Layer 3 — public connected-socket API and the per-connection driver task.
//!
//! The driver task owns the `core::Connection` and loops:
//!
//! ```text
//! select! {
//!     datagram from UDP (or from the listener demux channel)
//!         -> connection.handle_datagram(now, ..)
//!     sleep_until(connection.next_deadline())
//!         -> connection.handle_timer(now)
//!     command from the handle (send / close)
//!         -> connection.send(..) / connection.close(..)
//! }
//! // after every branch:
//! //   drain poll_transmit  -> encode -> udp send (send_to for listeners)
//! //   drain poll_deliver   -> data channel to the handle
//! //   on Closed            -> finish channels, exit task
//! ```
//!
//! The handle side communicates with the driver over mpsc channels; `Stats`
//! are shared through `Arc<Mutex<Stats>>` (updated by the driver after each
//! loop turn).

use std::{
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    sync::{
        atomic::{
            AtomicUsize,
            Ordering,
        },
        Arc,
        Mutex,
        PoisonError,
    },
    time::{
        Duration,
        Instant,
    },
};

use bytes::Bytes;
use tokio::{
    net::{
        ToSocketAddrs,
        UdpSocket,
    },
    sync::{
        mpsc,
        oneshot,
    },
    task::JoinHandle,
};
use tracing::{
    debug,
    trace,
    warn,
};

use crate::{
    core::{
        ConnState,
        Connection,
        Stats,
    },
    error::{
        CloseReason,
        SrtError,
    },
    listener::ReapGuard,
    net,
    options::SrtOptions,
    packet::{
        reject,
        Packet,
    },
};

/// Handle → driver command queue depth. Bounded: `send` backpressure is
/// fine — the driver never blocks on the core.
const CMD_QUEUE: usize = 256;

/// Scratch datagram buffer; larger than any negotiable MSS.
const RECV_BUF: usize = 65536;

/// TSBPD horizon used to flush the receive buffer once the connection is
/// closed: nothing more can arrive or be recovered, so the residual pacing
/// (at most the negotiated latency, ≤ 65535 ms) is abandoned in favor of a
/// prompt end-of-stream for `recv`.
const CLOSE_DRAIN_HORIZON: Duration = Duration::from_secs(70);

/// Command sent from the [`SrtSocket`] handle to its driver task.
pub(crate) enum Cmd {
    Send(Vec<u8>),
    Close,
}

/// Where the driver's datagrams come from and go to.
pub(crate) enum DriverIo {
    /// Caller mode: a connected UDP socket owned by the driver.
    Connected(UdpSocket),
    /// Accepted mode: datagrams demuxed by the listener driver arrive on
    /// `rx`; sends go through the shared listener socket via `send_to`.
    Demux {
        udp: Arc<UdpSocket>,
        remote: SocketAddrV4,
        rx: mpsc::Receiver<Vec<u8>>,
    },
}

enum RecvEvent {
    /// A datagram of this length was written into the scratch buffer.
    Buffered(usize),
    /// A demuxed datagram.
    Owned(Vec<u8>),
    /// Transient socket error (already logged); e.g. ECONNREFUSED from an
    /// ICMP port-unreachable while the peer is not up — the handshake
    /// timeout decides, never the socket error.
    Error,
    /// The demux source is gone (listener driver exited).
    Closed,
}

/// Result of one UDP send attempt. The sink classifies transport behavior but
/// deliberately does not log it; the output driver turns failures into public
/// counters without producing one event per packet.
#[must_use = "the output driver must account for every UDP send outcome"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendOutcome {
    Sent,
    IoError,
    Short,
}

/// Transport counters owned by the output driver. The sans-I/O core cannot
/// observe kernel send results, so these are overlaid onto its [`Stats`]
/// snapshot before publishing it to the socket handle.
#[derive(Default)]
struct OutputStats {
    udp_send_errors: u64,
    udp_short_sends: u64,
}

impl OutputStats {
    fn record(&mut self, outcome: SendOutcome) {
        match outcome {
            SendOutcome::Sent => {}
            SendOutcome::IoError => self.udp_send_errors += 1,
            SendOutcome::Short => self.udp_short_sends += 1,
        }
    }

    fn snapshot(&self, mut core: Stats) -> Stats {
        core.udp_send_errors = self.udp_send_errors;
        core.udp_short_sends = self.udp_short_sends;
        core
    }
}

impl DriverIo {
    /// Cancel-safe: both `UdpSocket::recv` and `mpsc::Receiver::recv` are.
    async fn recv(&mut self, buf: &mut [u8]) -> RecvEvent {
        match self {
            DriverIo::Connected(udp) => match udp.recv(buf).await {
                Ok(n) => RecvEvent::Buffered(n),
                Err(e) => {
                    debug!(%e, "udp recv error (transient)");
                    RecvEvent::Error
                }
            },
            DriverIo::Demux { rx, .. } => match rx.recv().await {
                Some(datagram) => RecvEvent::Owned(datagram),
                None => RecvEvent::Closed,
            },
        }
    }

    /// Sends one packet.
    /// On Unix targets data packets use two segments, avoiding
    /// the payload copy into `scratch`.
    /// Control packets and other targets keep the contiguous codec path.
    async fn send_packet(&self, packet: &Packet, scratch: &mut Vec<u8>) -> SendOutcome {
        #[cfg(all(unix, not(any(target_os = "horizon", target_os = "redox"))))]
        if let Packet::Data(data) = packet {
            return self.send_data_vectored(data).await;
        }

        scratch.clear();
        packet.encode(scratch);
        self.send_contiguous(scratch).await
    }

    /// Contiguous fallback and control-packet path.
    async fn send_contiguous(&self, data: &[u8]) -> SendOutcome {
        let result = match self {
            DriverIo::Connected(udp) => udp.send(data).await,
            DriverIo::Demux { udp, remote, .. } => udp.send_to(data, *remote).await,
        };
        classify_send(result, data.len())
    }

    /// Sends one SRT data packet as a single UDP datagram backed by two I/O
    /// vectors. `async_io` supplies Tokio readiness while `socket2` performs
    /// the platform `sendmsg` call without taking ownership of the socket.
    #[cfg(all(unix, not(any(target_os = "horizon", target_os = "redox"))))]
    async fn send_data_vectored(&self, data: &crate::packet::DataPacket) -> SendOutcome {
        let header = data.encode_header();
        let bufs = [
            std::io::IoSlice::new(&header),
            std::io::IoSlice::new(data.payload.as_ref()),
        ];
        let expected = header.len() + data.payload.len();
        let result = match self {
            DriverIo::Connected(udp) => {
                udp.async_io(tokio::io::Interest::WRITABLE, || {
                    socket2::SockRef::from(udp).send_vectored(&bufs)
                })
                .await
            }
            DriverIo::Demux { udp, remote, .. } => {
                let remote = socket2::SockAddr::from(std::net::SocketAddr::V4(*remote));
                udp.async_io(tokio::io::Interest::WRITABLE, || {
                    socket2::SockRef::from(udp.as_ref()).send_to_vectored(&bufs, &remote)
                })
                .await
            }
        };
        classify_send(result, expected)
    }
}

/// UDP sends are atomic on the supported platforms, so a short success is a
/// dropped datagram just as much as an error. The protocol's normal ARQ/control
/// repetition handles it; the driver must never stop on a transient I/O fault.
fn classify_send(result: std::io::Result<usize>, expected: usize) -> SendOutcome {
    match result {
        Ok(n) if n == expected => SendOutcome::Sent,
        Ok(_) => SendOutcome::Short,
        Err(_) => SendOutcome::IoError,
    }
}

/// Everything the driver task owns.
pub(crate) struct DriverState {
    pub conn: Connection,
    pub io: DriverIo,
    pub cmd_rx: mpsc::Receiver<Cmd>,
    pub data_tx: mpsc::Sender<Bytes>,
    pub stats: Arc<Mutex<Stats>>,
    pub close_reason: Arc<Mutex<Option<CloseReason>>>,
    /// Caller mode: signalled once on establishment (Ok) or terminal
    /// failure (Err). `None` for accepted connections.
    pub established_tx: Option<oneshot::Sender<Result<(), SrtError>>>,
    /// Listener demux cleanup, dropped when the driver exits.
    pub reap: Option<ReapGuard>,
    /// Effective payload size limit, shared with the handle's `send` check.
    /// Seeded from the connection at spawn; the driver overwrites it with
    /// the negotiated sender limit when a caller connection establishes
    /// (before signalling `established_tx`, so `connect` can never return
    /// a handle that still sees the pre-negotiation value).
    pub max_payload: Arc<AtomicUsize>,
}

/// Creates the handle/driver channel pair and spawns the driver task.
pub(crate) fn spawn_connection(
    conn: Connection,
    io: DriverIo,
    opts: &SrtOptions,
    established_tx: Option<oneshot::Sender<Result<(), SrtError>>>,
    reap: Option<ReapGuard>,
) -> SrtSocket {
    let (cmd_tx, cmd_rx) = mpsc::channel(CMD_QUEUE);
    let (data_tx, data_rx) = mpsc::channel(opts.recv_buffer_pkts.max(16));
    let stats = Arc::new(Mutex::new(conn.stats()));
    let close_reason = Arc::new(Mutex::new(None));
    let peer = conn.remote();
    let streamid = conn.streamid().map(str::to_owned);
    // Accepted connections are already established here, so this seed is
    // the negotiated limit; callers seed the configured cap and the driver
    // stores the negotiated one at establishment.
    let max_payload = Arc::new(AtomicUsize::new(conn.max_payload()));
    let driver = tokio::spawn(drive(DriverState {
        conn,
        io,
        cmd_rx,
        data_tx,
        stats: Arc::clone(&stats),
        close_reason: Arc::clone(&close_reason),
        established_tx,
        reap,
        max_payload: Arc::clone(&max_payload),
    }));
    SrtSocket {
        cmd_tx,
        data_rx,
        stats,
        close_reason,
        driver: Some(driver),
        peer,
        streamid,
        max_payload,
    }
}

/// The per-connection driver task (see the module docs for the loop shape).
async fn drive(state: DriverState) {
    let DriverState {
        mut conn,
        mut io,
        mut cmd_rx,
        data_tx,
        stats,
        close_reason,
        mut established_tx,
        reap,
        max_payload,
    } = state;
    // Dropped when this task returns → the listener reaps the demux entry.
    let _reap = reap;
    let mut buf = match io {
        DriverIo::Connected(_) => vec![0u8; RECV_BUF],
        DriverIo::Demux { .. } => Vec::new(),
    };
    let mut out = Vec::with_capacity(2048);
    let mut output_stats = OutputStats::default();
    let mut cmd_open = true;
    let mut announced = matches!(conn.state(), ConnState::Established);

    loop {
        // Drain everything the connection owes after the previous event
        // (including the very first turn: the caller's INDUCTION request is
        // queued at construction), then refresh the shared stats snapshot.
        let now = Instant::now();
        while let Some(packet) = conn.poll_transmit(now) {
            output_stats.record(io.send_packet(&packet, &mut out).await);
        }
        while let Some(payload) = conn.poll_deliver(now) {
            deliver(&data_tx, payload);
        }
        store(&stats, output_stats.snapshot(conn.stats()));

        match conn.state() {
            ConnState::Established if !announced => {
                announced = true;
                // Publish the negotiated payload limit BEFORE signalling
                // establishment: the oneshot rendezvous in `connect` then
                // guarantees the handle never observes the stale seed.
                max_payload.store(conn.max_payload(), Ordering::Relaxed);
                if let Some(tx) = established_tx.take() {
                    let _ = tx.send(Ok(()));
                }
            }
            ConnState::Closed(reason) => {
                store(&close_reason, Some(reason));
                if let Some(tx) = established_tx.take() {
                    let _ = tx.send(Err(connect_error(reason)));
                }
                // The SHUTDOWN (if owed) went out in the drain above.
                // Nothing further can arrive: flush whatever the receive
                // buffer still holds, in order, then end the data stream.
                let horizon = Instant::now() + CLOSE_DRAIN_HORIZON;
                while let Some(payload) = conn.poll_deliver(horizon) {
                    deliver(&data_tx, payload);
                }
                store(&stats, output_stats.snapshot(conn.stats()));
                debug!(%reason, "connection driver finished");
                return;
            }
            _ => {}
        }

        // Computed after the drains: they may have re-armed timers. `None`
        // (nothing scheduled) parks the task on the channels alone.
        let deadline = conn
            .next_deadline(Instant::now())
            .map(tokio::time::Instant::from_std);

        tokio::select! {
            event = io.recv(&mut buf) => match event {
                RecvEvent::Buffered(n) => conn.handle_datagram(Instant::now(), &buf[..n]),
                RecvEvent::Owned(datagram) => {
                    conn.handle_datagram_owned(Instant::now(), Bytes::from(datagram))
                }
                RecvEvent::Error => {}
                RecvEvent::Closed => {
                    warn!("datagram source closed; closing connection");
                    conn.close(Instant::now());
                }
            },
            cmd = cmd_rx.recv(), if cmd_open => match cmd {
                Some(Cmd::Send(payload)) => {
                    if let Err(e) = conn.send(Instant::now(), payload) {
                        // The handle's send() is fire-and-forget past the
                        // size check; live mode drops rather than stalls.
                        warn!(%e, "send failed; payload dropped");
                    }
                }
                Some(Cmd::Close) => conn.close(Instant::now()),
                None => {
                    cmd_open = false;
                    debug!("handle dropped; closing connection");
                    conn.close(Instant::now());
                }
            },
            _ = tokio::time::sleep_until(
                deadline.unwrap_or_else(tokio::time::Instant::now)
            ), if deadline.is_some() => {
                conn.handle_timer(Instant::now());
            }
        }
    }
}

/// Forwards one released payload to the handle. Never blocks the driver:
/// an application that stopped reading loses data (live semantics), not
/// protocol liveness.
fn deliver(data_tx: &mpsc::Sender<Bytes>, payload: Bytes) {
    match data_tx.try_send(payload) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!("application receive queue full; payload dropped");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            trace!("handle dropped; payload discarded");
        }
    }
}

fn store<T>(slot: &Mutex<T>, value: T) {
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = value;
}

fn load<T: Copy>(slot: &Mutex<T>) -> T {
    *slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Maps the close reason of a failed connect to the public error.
fn connect_error(reason: CloseReason) -> SrtError {
    match reason {
        CloseReason::ConnectTimeout => SrtError::ConnectTimeout,
        // Encryption mismatch rejections (encryption.md §8.1): BADSECRET =
        // wrong passphrase (from the listener), UNSECURE = a passphrase
        // on one side only — also the caller's local abort code, even for
        // a bad secret (§6.1).
        CloseReason::Rejected(reject::BADSECRET) => SrtError::WrongPassphrase,
        CloseReason::Rejected(reject::UNSECURE) => SrtError::EncryptionUnsupported,
        CloseReason::Rejected(code) => SrtError::Rejected(code),
        other => SrtError::Closed(other),
    }
}

/// A connected SRT socket (either an established caller connection or one
/// accepted by [`crate::SrtListener`]).
///
/// Dropping the handle closes the connection (the driver sends SHUTDOWN).
pub struct SrtSocket {
    cmd_tx: mpsc::Sender<Cmd>,
    data_rx: mpsc::Receiver<Bytes>,
    stats: Arc<Mutex<Stats>>,
    close_reason: Arc<Mutex<Option<CloseReason>>>,
    driver: Option<JoinHandle<()>>,
    peer: SocketAddrV4,
    streamid: Option<String>,
    /// Effective payload limit, shared with the driver (which stores the
    /// negotiated value at establishment). Relaxed ordering suffices: the
    /// `connect` oneshot rendezvous orders the store before any `send`.
    max_payload: Arc<AtomicUsize>,
}

impl SrtSocket {
    /// Caller mode: resolves `addr` (IPv4), performs the HSv5 handshake and
    /// returns an established socket.
    ///
    /// Errors: [`SrtError::ConnectTimeout`], [`SrtError::Rejected`],
    /// [`SrtError::EncryptionUnsupported`], [`SrtError::WrongPassphrase`],
    /// [`SrtError::InvalidPassphrase`], [`SrtError::InvalidKmParameters`],
    /// [`SrtError::InvalidBandwidth`], [`SrtError::NoIpv4Address`],
    /// [`SrtError::StreamIdTooLong`], [`SrtError::Io`].
    pub async fn connect(
        addr: impl ToSocketAddrs,
        opts: SrtOptions,
    ) -> Result<SrtSocket, SrtError> {
        if opts.streamid.as_ref().is_some_and(|s| s.len() > 512) {
            return Err(SrtError::StreamIdTooLong);
        }
        // Fail fast on invalid encryption options (encryption.md §2),
        // before any I/O: the handshake FSM consumes `crypto_config()`
        // internally and would otherwise fail closed without a
        // user-visible reason.
        opts.crypto_config()?;
        // Same fail-fast for pacing parameters: libsrt rejects them at
        // setsockopt; connect is this crate's earliest equivalent.
        opts.bandwidth.validate()?;
        let remote = net::resolve_v4(addr).await?;
        let udp = net::bind_udp(
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            opts.udp_recv_buffer,
        )?;
        udp.connect(remote).await?;
        let connect_timeout = opts.connect_timeout;
        let conn = Connection::connect(
            Instant::now(),
            remote,
            net::random_socket_id(),
            net::random_isn(),
            opts.clone(),
        );
        let (established_tx, established_rx) = oneshot::channel();
        let socket = spawn_connection(
            conn,
            DriverIo::Connected(udp),
            &opts,
            Some(established_tx),
            None,
        );
        // The core FSM enforces `connect_timeout` itself (it closes with
        // ConnectTimeout at the deadline and the driver signals the error);
        // the outer timeout is only a backstop against a stalled driver.
        match tokio::time::timeout(connect_timeout + Duration::from_secs(1), established_rx).await {
            Ok(Ok(Ok(()))) => Ok(socket),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) | Err(_) => Err(SrtError::ConnectTimeout),
        }
    }

    /// Receives the next data message in TSBPD order.
    ///
    /// The returned payload is a [`bytes::Bytes`]: cheap to clone and
    /// slice (refcounted, no copy).
    ///
    /// `Ok(None)` = clean end of stream (peer SHUTDOWN or local close);
    /// other terminations surface as [`SrtError::Closed`].
    ///
    /// Cancel-safe: no message is lost if the future is dropped.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, SrtError> {
        match self.data_rx.recv().await {
            Some(payload) => Ok(Some(payload)),
            // The driver always records the reason before finishing; a
            // missing one means the driver died — treat as a local close.
            None => match load(&self.close_reason) {
                Some(CloseReason::Shutdown) | Some(CloseReason::Local) | None => Ok(None),
                Some(reason) => Err(SrtError::Closed(reason)),
            },
        }
    }

    /// Sends one data message (≤ 1456 bytes for the default MSS; the limit
    /// follows the *negotiated* MSS — the min of both sides — so a peer
    /// with a smaller MSS lowers it).
    /// Live mode: never waits for the peer; buffer overflow drops the
    /// oldest unacknowledged packet.
    pub async fn send(&self, payload: &[u8]) -> Result<(), SrtError> {
        if payload.len() > self.max_payload.load(Ordering::Relaxed) {
            return Err(SrtError::PayloadTooLarge(payload.len()));
        }
        self.cmd_tx
            .send(Cmd::Send(payload.to_vec()))
            .await
            .map_err(|_| self.closed_error())
    }

    pub fn stats(&self) -> Stats {
        load(&self.stats)
    }

    pub fn peer_addr(&self) -> SocketAddrV4 {
        self.peer
    }

    /// StreamID of the connection (for accepted sockets: what the caller
    /// sent; for callers: the configured option).
    pub fn streamid(&self) -> Option<String> {
        self.streamid.clone()
    }

    /// Graceful close: sends SHUTDOWN and waits for the driver to finish.
    /// Buffered packets the pacer has not released yet are dropped, like
    /// any other unsent data (live semantics).
    pub async fn close(mut self) -> Result<(), SrtError> {
        // The driver may already be gone (peer close); that is not an error.
        let _ = self.cmd_tx.send(Cmd::Close).await;
        if let Some(driver) = self.driver.take() {
            let _ = driver.await;
        }
        Ok(())
    }

    fn closed_error(&self) -> SrtError {
        SrtError::Closed(load(&self.close_reason).unwrap_or(CloseReason::Local))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::ConnState,
        packet::{
            DataPacket,
            EncryptionFlags,
            MsgNumber,
            Packet,
            PacketPosition,
            SeqNumber,
            SocketId,
            Timestamp,
        },
    };

    fn opts() -> SrtOptions {
        SrtOptions::default()
    }

    fn data_packet(payload: Bytes) -> Packet {
        Packet::Data(DataPacket {
            seq: SeqNumber::new(0x1234_5678),
            position: PacketPosition::Only,
            order: false,
            encryption: EncryptionFlags::Even,
            retransmitted: true,
            msg_number: MsgNumber::new(7),
            timestamp: Timestamp(0x0102_0304),
            dst_socket_id: SocketId(0x0506_0708),
            payload,
        })
    }

    async fn assert_data_datagram(io: DriverIo, receiver: UdpSocket) {
        let packet = data_packet(Bytes::from_static(b"scatter/gather payload"));
        let mut expected = Vec::new();
        packet.encode(&mut expected);

        let sentinel = vec![0xA5; 32];
        let mut scratch = sentinel.clone();
        assert_eq!(
            io.send_packet(&packet, &mut scratch).await,
            SendOutcome::Sent
        );

        #[cfg(all(unix, not(any(target_os = "horizon", target_os = "redox"))))]
        assert_eq!(
            scratch, sentinel,
            "vectored data send must not touch the contiguous scratch buffer"
        );
        #[cfg(not(all(unix, not(any(target_os = "horizon", target_os = "redox")))))]
        assert_eq!(scratch, expected, "fallback must use the packet codec");

        let mut received = [0u8; 2048];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut received))
                .await
                .expect("timed out waiting for vectored datagram")
                .expect("receive vectored datagram");
        assert_eq!(&received[.. n], expected);
    }

    #[test]
    fn send_outcomes_are_classified_and_published_in_stats() {
        let io_error = std::io::Error::from(std::io::ErrorKind::Other);
        assert_eq!(classify_send(Ok(32), 32), SendOutcome::Sent);
        assert_eq!(classify_send(Ok(31), 32), SendOutcome::Short);
        assert_eq!(classify_send(Err(io_error), 32), SendOutcome::IoError);

        let mut output = OutputStats::default();
        output.record(SendOutcome::Sent);
        output.record(SendOutcome::IoError);
        output.record(SendOutcome::IoError);
        output.record(SendOutcome::Short);

        let snapshot = output.snapshot(Stats {
            pkts_sent: 7,
            bytes_sent: 700,
            ..Stats::default()
        });
        assert_eq!(snapshot.pkts_sent, 7, "core counters must be preserved");
        assert_eq!(snapshot.bytes_sent, 700, "core counters must be preserved");
        assert_eq!(snapshot.udp_send_errors, 2);
        assert_eq!(snapshot.udp_short_sends, 1);
    }

    #[tokio::test]
    async fn connected_data_send_is_one_vectored_datagram() {
        let sender = net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap();
        let receiver = net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap();
        sender
            .connect(receiver.local_addr().unwrap())
            .await
            .unwrap();

        assert_data_datagram(DriverIo::Connected(sender), receiver).await;
    }

    #[tokio::test]
    async fn demux_data_send_is_one_vectored_datagram() {
        let sender =
            Arc::new(net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap());
        let receiver = net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap();
        let remote = match receiver.local_addr().unwrap() {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => unreachable!(),
        };
        let (_tx, rx) = mpsc::channel(1);

        assert_data_datagram(
            DriverIo::Demux {
                udp: sender,
                remote,
                rx,
            },
            receiver,
        )
        .await;
    }

    /// Runs the in-memory HSv5 dance and returns the established caller
    /// and accepted connections (plus the caller's address).
    fn established_pair(
        t0: Instant,
        caller_opts: SrtOptions,
        listener_opts: SrtOptions,
    ) -> (Connection, Connection, SocketAddrV4) {
        use crate::{
            core::{
                Listener,
                ListenerAction,
                Timebase,
            },
            packet::{
                ControlPacket,
                ControlType,
                HandshakeCif,
            },
        };

        fn hs_cif(pkt: &Packet) -> &HandshakeCif {
            match pkt {
                Packet::Control(ControlPacket {
                    control_type: ControlType::Handshake(cif),
                    ..
                }) => cif,
                other => panic!("expected handshake, got {other:?}"),
            }
        }

        let caller_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 50_001);
        let mut c = Connection::connect(
            t0,
            caller_addr,
            SocketId(11),
            SeqNumber::new(5),
            caller_opts,
        );
        let mut l = Listener::new(net::random_u64(), Timebase::new(t0), listener_opts.clone());
        let ind = c.poll_transmit(t0).unwrap();
        let rsp = match l.handle_handshake(
            t0,
            caller_addr,
            hs_cif(&ind),
            SocketId(22),
            SeqNumber::new(0),
        ) {
            ListenerAction::Reply(p) => p,
            _ => panic!("expected reply"),
        };
        c.handle_packet(t0, rsp);
        let conc = c.poll_transmit(t0).unwrap();
        let (reply, negotiated) = match l.handle_handshake(
            t0,
            caller_addr,
            hs_cif(&conc),
            SocketId(22),
            SeqNumber::new(0),
        ) {
            ListenerAction::Accept { reply, negotiated } => (reply, negotiated),
            _ => panic!("expected accept"),
        };
        c.handle_packet(t0, reply.clone());
        assert_eq!(c.state(), ConnState::Established);
        let a = Connection::accepted(t0, *negotiated, reply, listener_opts);
        (c, a, caller_addr)
    }

    #[test]
    fn connect_error_mapping() {
        assert!(matches!(
            connect_error(CloseReason::ConnectTimeout),
            SrtError::ConnectTimeout
        ));
        // Encryption mismatches map to their own errors (encryption.md
        // §8.1): UNSECURE (1011) = passphrase on one side only, BADSECRET
        // (1010) = wrong passphrase.
        assert!(matches!(
            connect_error(CloseReason::Rejected(reject::UNSECURE)),
            SrtError::EncryptionUnsupported
        ));
        assert!(matches!(
            connect_error(CloseReason::Rejected(reject::BADSECRET)),
            SrtError::WrongPassphrase
        ));
        assert!(matches!(
            connect_error(CloseReason::Rejected(reject::BACKLOG)),
            SrtError::Rejected(reject::BACKLOG)
        ));
        assert!(matches!(
            connect_error(CloseReason::PeerIdle),
            SrtError::Closed(CloseReason::PeerIdle)
        ));
    }

    /// Invalid encryption options fail `connect` before any I/O: the
    /// target here cannot resolve, so reaching resolution would surface
    /// an [`SrtError::Io`] instead of the validation error.
    #[tokio::test]
    async fn connect_validates_crypto_options_before_io() {
        // Passphrase below the 10-byte minimum (encryption.md §2).
        let opts = SrtOptions::default().passphrase("short");
        let e = SrtSocket::connect(("host.invalid.", 1), opts)
            .await
            .err()
            .expect("invalid passphrase must fail connect");
        assert!(matches!(e, SrtError::InvalidPassphrase), "{e:?}");

        // km_preannounce > (km_refresh_rate - 1) / 2 (encryption.md §2).
        let mut opts = SrtOptions::default().passphrase("0123456789");
        opts.km_refresh_rate = Some(10);
        opts.km_preannounce = Some(9);
        let e = SrtSocket::connect(("host.invalid.", 1), opts)
            .await
            .err()
            .expect("invalid km parameters must fail connect");
        assert!(matches!(e, SrtError::InvalidKmParameters(_)), "{e:?}");
    }

    #[test]
    fn deliver_drops_on_full_without_blocking() {
        let (tx, mut rx) = mpsc::channel(1);
        deliver(&tx, vec![1].into());
        deliver(&tx, vec![2].into()); // dropped, must not panic or block
        assert_eq!(rx.try_recv().unwrap(), vec![1]);
        assert!(rx.try_recv().is_err());
        drop(rx);
        deliver(&tx, vec![3].into()); // closed, must not panic
    }

    /// The driver senses a dropped handle and closes the connection even
    /// mid-handshake (no peer at the far end).
    #[tokio::test]
    async fn dropped_handle_stops_driver() {
        let udp = net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap();
        // A bound-but-mute peer so sends do not raise ECONNREFUSED noise.
        let peer = net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap();
        let peer_addr = match peer.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        udp.connect(peer_addr).await.unwrap();
        let conn = Connection::connect(
            Instant::now(),
            peer_addr,
            SocketId(7),
            SeqNumber::new(1),
            opts(),
        );
        let (est_tx, est_rx) = oneshot::channel();
        let mut socket =
            spawn_connection(conn, DriverIo::Connected(udp), &opts(), Some(est_tx), None);
        let driver = socket.driver.take().expect("driver handle");
        drop(socket);
        // The driver must exit promptly (well before the 3 s handshake
        // timeout would fire).
        tokio::time::timeout(Duration::from_secs(1), driver)
            .await
            .expect("driver did not exit after handle drop")
            .expect("driver panicked");
        // A caller abandoning a handshake fails the establishment signal.
        let err = est_rx.await.expect("signal");
        assert!(
            matches!(err, Err(SrtError::Closed(CloseReason::Local))),
            "{err:?}"
        );
    }

    /// Closed-state drain: a connection closed by SHUTDOWN flushes buffered
    /// payloads to the data channel before the channel ends.
    #[tokio::test]
    async fn driver_drains_receiver_after_close() {
        // Build an in-memory established pair: `a` is driven by the task,
        // `c` is puppeteered by the test through a demux channel.
        let t0 = Instant::now();
        let (mut c, a, caller_addr) = established_pair(t0, opts(), opts());

        // Drive `a` in a task; feed it data + SHUTDOWN from `c`.
        let udp = Arc::new(net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap());
        let (demux_tx, demux_rx) = mpsc::channel(64);
        let mut socket = spawn_connection(
            a,
            DriverIo::Demux {
                udp,
                remote: caller_addr,
                rx: demux_rx,
            },
            &opts(),
            None,
            None,
        );
        let now = Instant::now();
        c.send(now, b"one".to_vec()).unwrap();
        c.send(now, b"two".to_vec()).unwrap();
        let mut out = Vec::new();
        while let Some(p) = c.poll_transmit(now) {
            out.clear();
            p.encode(&mut out);
            demux_tx.send(out.clone()).await.unwrap();
        }
        c.close(now);
        while let Some(p) = c.poll_transmit(now) {
            out.clear();
            p.encode(&mut out);
            demux_tx.send(out.clone()).await.unwrap();
        }
        // Both payloads must drain (TSBPD pacing abandoned on close), then
        // a clean end of stream.
        let r = tokio::time::timeout(Duration::from_secs(5), socket.recv())
            .await
            .expect("recv timed out");
        assert_eq!(r.unwrap(), Some(Bytes::from_static(b"one")));
        assert_eq!(
            socket.recv().await.unwrap(),
            Some(Bytes::from_static(b"two"))
        );
        assert_eq!(socket.recv().await.unwrap(), None, "clean EOF after drain");
    }

    /// Accepted sockets enforce the *negotiated* payload limit, not the
    /// locally configured one: a caller advertising MSS 1360 lowers the
    /// limit to 1316 even though the listener's own MSS (1500) would allow
    /// 1456. Before the fix, `send` accepted such payloads and the driver
    /// silently dropped them (`sender.push` → PayloadTooLarge, only logged).
    #[tokio::test]
    async fn accepted_send_limit_uses_negotiated_mss() {
        let t0 = Instant::now();
        let caller_opts = SrtOptions {
            mss: 1360,
            ..SrtOptions::default()
        };
        let (_c, a, caller_addr) = established_pair(t0, caller_opts, opts());

        let udp = Arc::new(net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap());
        // Kept alive so the driver does not see a closed demux source.
        let (_demux_tx, demux_rx) = mpsc::channel(16);
        let socket = spawn_connection(
            a,
            DriverIo::Demux {
                udp,
                remote: caller_addr,
                rx: demux_rx,
            },
            &opts(), // local options alone would permit 1456
            None,
            None,
        );
        let r = socket.send(&[0u8; 1400]).await;
        assert!(matches!(r, Err(SrtError::PayloadTooLarge(1400))), "{r:?}");
        socket
            .send(&[0u8; 1316])
            .await
            .expect("payload at the negotiated limit");
    }

    /// Caller sockets adopt the *negotiated* payload limit before `connect`
    /// returns: a listener with MSS 1360 lowers the limit to 1316 even
    /// though the caller's default MSS (1500) would allow 1456. Before the
    /// fix, every payload in (1316, 1456] passed `send` and was silently
    /// dropped by the driver.
    #[tokio::test]
    async fn caller_send_limit_uses_negotiated_mss() {
        use crate::{
            core::{
                Listener,
                ListenerAction,
                Timebase,
            },
            packet::{
                ControlPacket,
                ControlType,
            },
        };

        let peer = net::bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).unwrap();
        let peer_addr = match peer.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        // Puppet peer: answers the caller's handshake from a Listener FSM
        // configured with a smaller MSS, then exits.
        let listener_opts = SrtOptions {
            mss: 1360,
            ..SrtOptions::default()
        };
        let mut l = Listener::new(
            net::random_u64(),
            Timebase::new(Instant::now()),
            listener_opts,
        );
        let puppet = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, from) = peer.recv_from(&mut buf).await.unwrap();
                let from = match from {
                    std::net::SocketAddr::V4(a) => a,
                    _ => unreachable!(),
                };
                let pkt = Packet::parse(&buf[.. n]).unwrap();
                let cif = match &pkt {
                    Packet::Control(ControlPacket {
                        control_type: ControlType::Handshake(cif),
                        ..
                    }) => cif,
                    other => panic!("puppet expected a handshake, got {other:?}"),
                };
                let (reply, accepted) = match l.handle_handshake(
                    Instant::now(),
                    from,
                    cif,
                    SocketId(99),
                    SeqNumber::new(1000),
                ) {
                    ListenerAction::Reply(p) => (p, false),
                    ListenerAction::Accept { reply, .. } => (reply, true),
                    _ => panic!("unexpected listener action"),
                };
                let mut out = Vec::new();
                reply.encode(&mut out);
                peer.send_to(&out, from).await.unwrap();
                if accepted {
                    return;
                }
            }
        });

        let socket = SrtSocket::connect(peer_addr, opts())
            .await
            .expect("connect");
        puppet.await.expect("puppet");
        // Negotiated MSS = min(1500, 1360) = 1360 → payload limit 1316.
        let r = socket.send(&[0u8; 1400]).await;
        assert!(matches!(r, Err(SrtError::PayloadTooLarge(1400))), "{r:?}");
        socket
            .send(&[0u8; 1316])
            .await
            .expect("payload at the negotiated limit");
    }
}
