//! Free-port allocation for parallel tests.

use std::net::{
    Ipv4Addr,
    SocketAddr,
    SocketAddrV4,
    UdpSocket,
};

/// Reserves a currently-free UDP port on 127.0.0.1 by binding port 0, reading
/// the kernel-assigned port, and dropping the socket.
///
/// Safe for tests running in parallel: each call gets a distinct ephemeral
/// port from the kernel. There is an inherent race between dropping the
/// probe socket and the test binding the port, but the kernel cycles through
/// the ephemeral range before reuse, so collisions within a test run are not
/// a practical concern. (Binding the *final* socket to port 0 directly is
/// still preferable whenever the test controls the bind itself; use this
/// helper when a port number must be known up front, e.g. to build an
/// `srt://:port` URI.)
pub fn free_udp_port() -> std::io::Result<u16> {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(sock.local_addr()?.port())
}

/// [`free_udp_port`] packaged as a full `127.0.0.1:port` address.
pub fn free_udp_addr() -> std::io::Result<SocketAddr> {
    Ok(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        free_udp_port()?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocated_port_is_bindable() {
        let port = free_udp_port().unwrap();
        assert_ne!(port, 0);
        // The probe socket was dropped, so binding the same port must work.
        UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    }

    #[test]
    fn concurrent_allocations_are_distinct_while_held() {
        // While probe sockets are alive the kernel cannot hand out the same
        // port twice; emulate parallel allocation by holding several binds.
        let socks: Vec<UdpSocket> = (0 .. 8)
            .map(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
            .collect();
        let mut ports: Vec<u16> = socks
            .iter()
            .map(|s| s.local_addr().unwrap().port())
            .collect();
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), 8);
    }

    #[test]
    fn free_udp_addr_is_loopback() {
        let addr = free_udp_addr().unwrap();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);
    }
}
