//! Free-port allocation for parallel tests.

use std::{
    net::{
        Ipv4Addr,
        SocketAddr,
        SocketAddrV4,
        UdpSocket,
    },
    sync::atomic::{
        AtomicUsize,
        Ordering,
    },
};

/// First port of the reserved test range.
///
/// The range sits *below* every mainstream platform's ephemeral (autobind)
/// range — Linux defaults to 32768–60999 (`/proc/sys/net/ipv4/
/// ip_local_port_range`), macOS and Windows to 49152–65535 — so a socket
/// bound to port 0 can never be handed one of our ports. That is what makes
/// the handoff safe: between the probe below and the final bind by the test
/// (or an external process like `srt-live-transmit`) the port is technically
/// unbound, but nothing can acquire it — autobind never picks from this
/// range, and [`NEXT_OFFSET`] never re-issues it.
const RANGE_START: u16 = 20000;

/// Number of ports in the reserved range (`20000 ..= 29999`).
const RANGE_LEN: u16 = 10000;

/// Next allocation number, monotonically increasing: a port handed out once
/// is never handed out again within this test binary (until a full wrap of
/// the 10 000-port range, far beyond what any run allocates). Test binaries
/// run sequentially under `cargo test`, and [`candidate_port`] spreads
/// concurrently-running binaries by PID besides.
static NEXT_OFFSET: AtomicUsize = AtomicUsize::new(0);

/// The candidate port for allocation number `n`. The PID-derived offset
/// starts each test binary in its own part of the range, so even binaries
/// running in parallel (e.g. under `cargo nextest`) rarely probe the same
/// ports.
fn candidate_port(n: usize) -> u16 {
    let spread = std::process::id() as usize * 6151; // arbitrary prime stride
    RANGE_START + ((spread + n) % RANGE_LEN as usize) as u16
}

/// Reserves a currently-free UDP port on 127.0.0.1 from a dedicated test
/// range outside the kernel's ephemeral range.
///
/// Safe for tests running in parallel and for handing the number to another
/// process (e.g. an `srt://:port` URI for `srt-live-transmit`): the global
/// counter never re-issues a port within this binary, and because the range
/// is outside the autobind range no bind-to-port-0 socket elsewhere can
/// steal the port while it awaits its final bind. (A plain bind-port-0 +
/// read-back probe has neither guarantee — UDP autobind starts from a
/// *random* point in the ephemeral range on every call, so a just-dropped
/// probe port is immediately re-issuable to anyone.) The bind probe below
/// only skips ports held by unrelated services. Binding the *final* socket
/// to port 0 directly is still preferable whenever the test controls the
/// bind itself; use this helper when a port number must be known up front.
pub fn free_udp_port() -> std::io::Result<u16> {
    for _ in 0 .. RANGE_LEN {
        let port = candidate_port(NEXT_OFFSET.fetch_add(1, Ordering::Relaxed));
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            // Free right now, and nothing can re-acquire it behind our back
            // (see above) — safe to hand out even though the probe socket
            // is dropped here.
            Ok(_) => return Ok(port),
            // Held by a leftover process or an unrelated service: skip it.
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        "no free UDP port in the reserved test range",
    ))
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
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn allocated_port_is_bindable() {
        let port = free_udp_port().unwrap();
        assert_ne!(port, 0);
        // The probe socket was dropped, so binding the same port must work.
        UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    }

    #[test]
    fn ports_come_from_the_reserved_range() {
        for _ in 0 .. 8 {
            let port = free_udp_port().unwrap();
            assert!(
                (RANGE_START .. RANGE_START + RANGE_LEN).contains(&port),
                "port {port} outside reserved range"
            );
        }
    }

    /// Regression test: dropping the probe socket must not make the port
    /// re-issuable. The old bind-port-0 probe let the kernel hand a
    /// just-freed port to the next caller (UDP autobind picks a random
    /// start, with no reuse avoidance), so two tests could draw the same
    /// port and race their `srt-live-transmit` listeners onto it. The
    /// monotonic counter makes distinctness an invariant, not a die roll.
    #[test]
    fn released_ports_are_never_reissued() {
        let mut seen = HashSet::new();
        for _ in 0 .. 100 {
            // Each probe socket is dropped inside free_udp_port, so every
            // previously returned port is free again — and must still not
            // come back.
            let port = free_udp_port().unwrap();
            assert!(seen.insert(port), "port {port} issued twice");
        }
    }

    /// A port occupied by someone else (leftover process, unrelated
    /// service) must be skipped, not handed out.
    #[test]
    fn busy_ports_are_skipped() {
        // Occupy a run of upcoming candidates. Concurrent tests may bump
        // the counter past some of them, but any allocation landing on a
        // held candidate must skip it.
        let base = NEXT_OFFSET.load(Ordering::Relaxed);
        let held: Vec<UdpSocket> = (base .. base + 16)
            .filter_map(|n| {
                UdpSocket::bind((Ipv4Addr::LOCALHOST, candidate_port(n))).ok()
            })
            .collect();
        let held_ports: HashSet<u16> = held
            .iter()
            .map(|s| s.local_addr().unwrap().port())
            .collect();
        assert!(!held_ports.is_empty(), "could not occupy any candidate");
        let port = free_udp_port().unwrap();
        assert!(
            !held_ports.contains(&port),
            "free_udp_port returned busy port {port}"
        );
    }

    /// The no-theft guarantee rests on the reserved range not overlapping
    /// the kernel's autobind range; verify that against the live kernel
    /// setting. Fails if the constants drift into the ephemeral range or
    /// the machine uses a non-default `ip_local_port_range` that breaks
    /// the assumption (a true positive: the allocator is unsafe there).
    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_range_avoids_kernel_autobind_range() {
        let raw = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .expect("read ip_local_port_range");
        let mut it = raw.split_whitespace();
        let low: u16 = it.next().unwrap().parse().unwrap();
        let high: u16 = it.next().unwrap().parse().unwrap();
        let end = RANGE_START + RANGE_LEN - 1;
        assert!(
            end < low || RANGE_START > high,
            "reserved range {RANGE_START}-{end} overlaps ephemeral range {low}-{high}"
        );
    }

    #[test]
    fn free_udp_addr_is_loopback() {
        let addr = free_udp_addr().unwrap();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);
    }
}
