//! Runtime helpers: UDP socket construction and dependency-free randomness.

use std::{
    collections::hash_map::RandomState,
    hash::{
        BuildHasher,
        Hasher,
    },
    io,
    net::SocketAddr,
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
pub(crate) fn bind_udp(addr: SocketAddr, recv_buffer: Option<usize>) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    // Keep the address family explicit on every platform: IPv4-mapped
    // traffic must not unexpectedly share an IPv6 listener's port.
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    if let Some(bytes) = recv_buffer {
        socket.set_recv_buffer_size(bytes)?;
    }
    socket.bind(&addr.into())?;
    let socket = std::net::UdpSocket::from(socket);
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// Resolves either family in the order returned by `lookup_host`.
/// An explicit source address restricts resolution to its own family.
pub(crate) async fn resolve(
    addr: impl ToSocketAddrs,
    local: Option<SocketAddr>,
) -> Result<SocketAddr, SrtError> {
    select_ip(tokio::net::lookup_host(addr).await?, local)
}

fn select_ip(
    mut addrs: impl Iterator<Item = SocketAddr>,
    local: Option<SocketAddr>,
) -> Result<SocketAddr, SrtError> {
    addrs
        .find(|addr| local.is_none_or(|local| local.is_ipv4() == addr.is_ipv4()))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no target address matches the requested IP family",
            )
            .into()
        })
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
        let a = bind_udp(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            Some(256 * 1024),
        )
        .expect("bind a");
        let b = bind_udp(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), None).expect("bind b");
        let addr_a = a.local_addr().expect("local addr");
        b.send_to(b"ping", addr_a).await.expect("send");
        let mut buf = [0u8; 16];
        let (n, from) = a.recv_from(&mut buf).await.expect("recv");
        assert_eq!(&buf[.. n], b"ping");
        assert_eq!(from, b.local_addr().unwrap());
    }

    /// A second binder that sets `SO_REUSEADDR` (as libsrt does by default)
    /// must get `AddrInUse`. If `bind_udp` ever sets `SO_REUSEADDR`, the rival
    /// bind succeeds and the kernel silently redirects all unicast datagrams
    /// to it — this test then fails.
    #[tokio::test]
    async fn bind_udp_is_exclusive_against_reuseaddr_rival() {
        let first =
            bind_udp(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), None).expect("first bind");
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
    async fn resolve_literals_and_source_family() {
        let v4: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let v6: SocketAddr = "[::1]:9000".parse().unwrap();
        assert_eq!(resolve("[::1]:9000", None).await.unwrap(), v6);
        assert_eq!(resolve("127.0.0.1:9000", None).await.unwrap(), v4);
        assert_eq!(select_ip([v6, v4].into_iter(), None).unwrap(), v6);
        assert_eq!(select_ip([v4, v6].into_iter(), None).unwrap(), v4);
        assert_eq!(select_ip([v4, v6].into_iter(), Some(v6)).unwrap(), v6);
        assert_eq!(select_ip([v6, v4].into_iter(), Some(v4)).unwrap(), v4);
        assert!(select_ip([v4].into_iter(), Some(v6)).is_err());
        assert!(select_ip([v6].into_iter(), Some(v4)).is_err());
        assert!(select_ip([].into_iter(), None).is_err());
        // Resolution must retain the interface scope for link-local peers.
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1234".parse().unwrap(),
            9000,
            0,
            7,
        ));
        assert_eq!(resolve(scoped, Some(v6)).await.unwrap(), scoped);
    }

    #[tokio::test]
    async fn ipv6_bind_roundtrip_and_exclusive_port() {
        let a = bind_udp("[::1]:0".parse::<SocketAddr>().unwrap(), Some(256 * 1024)).unwrap();
        let b = bind_udp("[::1]:0".parse::<SocketAddr>().unwrap(), None).unwrap();
        assert!(socket2::SockRef::from(&a).only_v6().unwrap());
        b.send_to(b"ipv6", a.local_addr().unwrap()).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = a.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[.. n], b"ipv6");
        assert_eq!(from, b.local_addr().unwrap());
        let err = bind_udp(a.local_addr().unwrap(), None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }
}
