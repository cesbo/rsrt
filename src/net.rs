//! Runtime helpers: UDP socket construction and dependency-free randomness.

use std::{
    collections::hash_map::RandomState,
    hash::{
        BuildHasher,
        Hasher,
    },
    io,
    net::{
        SocketAddr,
        SocketAddrV4,
    },
    sync::{
        atomic::{
            AtomicU64,
            Ordering,
        },
        OnceLock,
    },
};

use socket2::{
    Domain,
    Protocol,
    Socket,
    Type,
};
use tokio::net::{
    ToSocketAddrs,
    UdpSocket,
};

use crate::{
    error::SrtError,
    packet::{
        SeqNumber,
        SocketId,
    },
};

/// Binds a UDP socket (constructed via `socket2` so the receive buffer can
/// be sized before `bind`), then converts it for tokio:
/// `set_nonblocking(true)` → `UdpSocket::from_std`. Must be called within a
/// tokio runtime.
///
/// Deliberately does NOT set `SO_REUSEADDR`: this library has no shared-fd
/// multiplexer, so two sockets on one port can never cooperate — a duplicate
/// bind must fail with `AddrInUse` instead of silently stealing all inbound
/// traffic from the first socket (which is what the kernel does for unicast
/// UDP when both binders set `SO_REUSEADDR`).
pub(crate) fn bind_udp(addr: SocketAddrV4, recv_buffer: Option<usize>) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if let Some(bytes) = recv_buffer {
        socket.set_recv_buffer_size(bytes)?;
    }
    socket.bind(&SocketAddr::V4(addr).into())?;
    let socket = std::net::UdpSocket::from(socket);
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// Resolves `addr` to the first IPv4 address ([`SrtError::NoIpv4Address`]
/// if none). Uses `tokio::net::lookup_host`.
pub(crate) async fn resolve_v4(addr: impl ToSocketAddrs) -> Result<SocketAddrV4, SrtError> {
    let mut addrs = tokio::net::lookup_host(addr).await?;
    addrs
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .ok_or(SrtError::NoIpv4Address)
}

/// Non-zero random value without external dependencies: SipHash keyed once
/// per process from OS entropy (`RandomState`), fed a process-wide counter.
/// The low 32 bits are never zero, so no truncation of the result can
/// produce the reserved socket id 0.
pub(crate) fn random_u64() -> u64 {
    static STATE: OnceLock<RandomState> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let state = STATE.get_or_init(RandomState::new);
    loop {
        let mut hasher = state.build_hasher();
        hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
        let value = hasher.finish();
        if value as u32 != 0 {
            return value;
        }
    }
}

/// Random non-zero local socket id. The MSB is kept clear: later libsrt
/// versions use it to mark bonding-group ids.
pub(crate) fn random_socket_id() -> SocketId {
    loop {
        let id = random_u64() as u32 & 0x7FFF_FFFF;
        if id != 0 {
            return SocketId(id);
        }
    }
}

/// Random ISN in `[0, 0x7FFF_FFFE]`: the peer's `valid()` check requires
/// `ISN < 0x7FFF_FFFF` (docs/spec/NOTES.md).
pub(crate) fn random_isn() -> SeqNumber {
    SeqNumber::new((random_u64() % 0x7FFF_FFFF) as u32)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn random_u64_low_word_never_zero_and_varies() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0 .. 10_000 {
            let v = random_u64();
            assert_ne!(v as u32, 0);
            seen.insert(v);
        }
        // SipHash of distinct counters: collisions are astronomically rare.
        assert!(seen.len() > 9_990, "values look non-random: {}", seen.len());
    }

    #[test]
    fn random_socket_id_in_range() {
        for _ in 0 .. 10_000 {
            let id = random_socket_id();
            assert_ne!(id, SocketId::HANDSHAKE);
            assert_eq!(id.0 & 0x8000_0000, 0, "MSB must stay clear");
        }
    }

    #[test]
    fn random_isn_in_valid_range() {
        for _ in 0 .. 10_000 {
            let isn = random_isn();
            assert!(isn.value() <= 0x7FFF_FFFE, "ISN out of range: {isn}");
        }
    }

    #[tokio::test]
    async fn bind_udp_roundtrip() {
        let a =
            bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), Some(256 * 1024)).expect("bind a");
        let b = bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).expect("bind b");
        let addr_a = a.local_addr().expect("local addr");
        b.send_to(b"ping", addr_a).await.expect("send");
        let mut buf = [0u8; 16];
        let (n, from) = a.recv_from(&mut buf).await.expect("recv");
        assert_eq!(&buf[.. n], b"ping");
        assert_eq!(from, b.local_addr().unwrap());
    }

    /// A second binder that sets `SO_REUSEADDR` (as libsrt does by default,
    /// and as this library did via the `udp` crate before the fix) must get
    /// `AddrInUse`. If `bind_udp` ever sets `SO_REUSEADDR` again, the rival
    /// bind succeeds and the kernel silently redirects all unicast datagrams
    /// to it — this test then fails.
    #[tokio::test]
    async fn bind_udp_is_exclusive_against_reuseaddr_rival() {
        let first = bind_udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), None).expect("first bind");
        let addr = first.local_addr().expect("local addr");

        let rival =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("rival socket");
        rival.set_reuse_address(true).expect("set SO_REUSEADDR");
        let err = rival
            .bind(&addr.into())
            .expect_err("duplicate bind on an SRT port must fail");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn resolve_v4_literal() {
        let addr = resolve_v4("127.0.0.1:9000").await.expect("resolve");
        assert_eq!(addr, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9000));
    }

    #[tokio::test]
    async fn resolve_v4_rejects_v6_only() {
        match resolve_v4("[::1]:9000").await {
            Err(SrtError::NoIpv4Address) => {}
            other => panic!("expected NoIpv4Address, got {other:?}"),
        }
    }
}
