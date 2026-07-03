//! Connection options.

use std::time::Duration;

/// Options for callers (`SrtSocket::connect`) and listeners
/// (`SrtListener::bind`). Defaults follow libsrt 1.4.4 live mode.
///
/// There is deliberately no passphrase option: encryption is unsupported and
/// encrypted peers are rejected.
#[derive(Debug, Clone)]
pub struct SrtOptions {
    /// Receiver-side TSBPD latency we request for the data we *receive*
    /// (SRTO_RCVLATENCY). Effective latency is the max of this and the
    /// peer's proposed sender latency. Default 120 ms.
    pub latency: Duration,
    /// Latency we propose for the data we *send* (SRTO_PEERLATENCY).
    /// Default 0 (peer's receiver latency wins).
    pub peer_latency: Duration,
    /// StreamID sent by a caller (SRTO_STREAMID), max 512 bytes.
    pub streamid: Option<String>,
    /// MTU including IP/UDP headers (SRTO_MSS). Default 1500.
    pub mss: u32,
    /// Maximum flow window (packets in flight). Default 8192.
    pub flow_window: u32,
    /// Receive buffer capacity, packets. Default 8192.
    pub recv_buffer_pkts: usize,
    /// Send buffer capacity, packets. Default 8192.
    pub send_buffer_pkts: usize,
    /// Caller handshake overall timeout. Default 3 s.
    pub connect_timeout: Duration,
    /// Connection is broken after this long without any packet from the
    /// peer. Default 5 s.
    pub peer_idle_timeout: Duration,
    /// UDP socket receive buffer size in bytes (SO_RCVBUF), if set.
    pub udp_recv_buffer: Option<usize>,
}

impl Default for SrtOptions {
    fn default() -> Self {
        SrtOptions {
            latency: Duration::from_millis(120),
            peer_latency: Duration::ZERO,
            streamid: None,
            mss: 1500,
            flow_window: 8192,
            recv_buffer_pkts: 8192,
            send_buffer_pkts: 8192,
            connect_timeout: Duration::from_secs(3),
            peer_idle_timeout: Duration::from_secs(5),
            udp_recv_buffer: None,
        }
    }
}

impl SrtOptions {
    /// Maximum live-mode payload per packet: MSS − 28 (IPv4+UDP) − 16 (SRT).
    pub fn max_payload(&self) -> usize {
        (self.mss as usize).saturating_sub(44)
    }

    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    pub fn peer_latency(mut self, latency: Duration) -> Self {
        self.peer_latency = latency;
        self
    }

    pub fn streamid(mut self, streamid: impl Into<String>) -> Self {
        self.streamid = Some(streamid.into());
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn peer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.peer_idle_timeout = timeout;
        self
    }
}
