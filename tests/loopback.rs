//! Loopback integration tests: caller ↔ listener over 127.0.0.1 with real
//! tokio time. Each test stays well under ~10 s.

use std::{
    net::Ipv4Addr,
    time::{
        Duration,
        Instant,
    },
};

use srt::{
    SrtError,
    SrtListener,
    SrtOptions,
    SrtSocket,
};

/// Deterministic message `i`: 4-byte BE index followed by LCG bytes.
fn message(i: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&i.to_be_bytes());
    let mut x = i.wrapping_mul(2_654_435_761).wrapping_add(0x9E37_79B9);
    while out.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((x >> 24) as u8);
    }
    out
}

/// Establishes a caller ↔ accepted pair through a fresh listener.
async fn pair(copts: SrtOptions, lopts: SrtOptions) -> (SrtSocket, SrtSocket, SrtListener) {
    let mut listener = SrtListener::bind("127.0.0.1:0", lopts)
        .await
        .expect("listener bind");
    let addr = listener.local_addr();
    assert_eq!(*addr.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(addr.port(), 0);
    let (caller, accepted) = tokio::join!(SrtSocket::connect(addr, copts), listener.accept());
    let caller = caller.expect("connect");
    let (accepted, peer) = accepted.expect("accept");
    assert_eq!(*peer.ip(), Ipv4Addr::LOCALHOST);
    assert_eq!(peer, accepted.peer_addr());
    assert_eq!(caller.peer_addr(), addr);
    (caller, accepted, listener)
}

#[tokio::test]
async fn connect_and_accept() {
    let (caller, accepted, _listener) = tokio::time::timeout(
        Duration::from_secs(5),
        pair(SrtOptions::default(), SrtOptions::default()),
    )
    .await
    .expect("handshake timed out");
    // No streamid was configured.
    assert_eq!(caller.streamid(), None);
    assert_eq!(accepted.streamid(), None);
    caller.close().await.expect("caller close");
    accepted.close().await.expect("accepted close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unidirectional_2000_messages_in_order() {
    const COUNT: u32 = 2000;
    const LEN: usize = 1316;

    let copts = SrtOptions::default().latency(Duration::from_millis(120));
    // Generous UDP receive buffer on the listener socket (the receiving
    // side); the kernel clamps to rmem_max silently.
    let mut lopts = SrtOptions::default().latency(Duration::from_millis(120));
    lopts.udp_recv_buffer = Some(4 << 20);

    let (caller, mut accepted, _listener) = pair(copts, lopts).await;

    let send_task = tokio::spawn(async move {
        for i in 0 .. COUNT {
            caller.send(&message(i, LEN)).await.expect("send");
            // Light pacing keeps the loopback kernel buffer comfortable.
            if i % 25 == 24 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        // Let ARQ settle before SHUTDOWN tears the connection down.
        tokio::time::sleep(Duration::from_millis(500)).await;
        caller.close().await.expect("close");
    });

    let recv_task = async {
        let mut next = 0u32;
        while let Some(payload) = accepted.recv().await.expect("recv") {
            assert_eq!(
                payload,
                message(next, LEN),
                "message {next} corrupted or out of order"
            );
            next += 1;
        }
        assert_eq!(next, COUNT, "stream ended early");
    };
    tokio::time::timeout(Duration::from_secs(9), recv_task)
        .await
        .expect("receive timed out");
    send_task.await.expect("send task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bidirectional_simultaneous() {
    const COUNT: u32 = 300;
    const LEN: usize = 700;

    let (caller, accepted, _listener) = pair(SrtOptions::default(), SrtOptions::default()).await;

    // Both directions in flight at once; each task sends its stream, then
    // drains the opposite one (buffers hold COUNT messages comfortably).
    async fn pump(mut sock: SrtSocket, tag: u32) -> SrtSocket {
        for i in 0 .. COUNT {
            sock.send(&message(tag.wrapping_add(i), LEN))
                .await
                .expect("send");
            if i % 50 == 49 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let want_tag: u32 = if tag == 0 { 1_000_000 } else { 0 };
        for i in 0 .. COUNT {
            let payload = sock.recv().await.expect("recv").expect("unexpected EOF");
            assert_eq!(payload, message(want_tag.wrapping_add(i), LEN));
        }
        sock
    }

    let caller_side = tokio::spawn(pump(caller, 0));
    let accepted_side = tokio::spawn(pump(accepted, 1_000_000));
    let run = async {
        let caller = caller_side.await.expect("caller task");
        let accepted = accepted_side.await.expect("accepted task");
        caller.close().await.expect("caller close");
        accepted.close().await.expect("accepted close");
    };
    tokio::time::timeout(Duration::from_secs(9), run)
        .await
        .expect("bidirectional test timed out");
}

#[tokio::test]
async fn streamid_visible_on_accepted_side() {
    let copts = SrtOptions::default().streamid("live/cam-42");
    let (caller, accepted, _listener) = pair(copts, SrtOptions::default()).await;
    assert_eq!(accepted.streamid().as_deref(), Some("live/cam-42"));
    assert_eq!(caller.streamid().as_deref(), Some("live/cam-42"));
    caller.close().await.unwrap();
    accepted.close().await.unwrap();
}

#[tokio::test]
async fn clean_close_yields_none_after_drain() {
    const COUNT: u32 = 5;
    let (caller, mut accepted, _listener) =
        pair(SrtOptions::default(), SrtOptions::default()).await;

    for i in 0 .. COUNT {
        caller.send(&message(i, 100)).await.expect("send");
    }
    caller.close().await.expect("close");

    let run = async {
        for i in 0 .. COUNT {
            let payload = accepted.recv().await.expect("recv");
            assert_eq!(payload, Some(message(i, 100)), "message {i}");
        }
        // Peer SHUTDOWN is a clean end of stream, not an error.
        assert_eq!(accepted.recv().await.expect("recv after close"), None);
    };
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("drain timed out");
    let stats = accepted.stats();
    assert_eq!(stats.pkts_recv, u64::from(COUNT));
}

#[tokio::test]
async fn connect_to_dead_port_times_out() {
    // Grab an ephemeral port with no listener behind it.
    let port = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        probe.local_addr().expect("probe addr").port()
    };
    let started = Instant::now();
    let result = SrtSocket::connect(("127.0.0.1", port), SrtOptions::default()).await;
    let elapsed = started.elapsed();
    match result {
        Err(SrtError::ConnectTimeout) => {}
        Err(other) => panic!("expected ConnectTimeout, got {other:?}"),
        Ok(_) => panic!("expected ConnectTimeout, got a connection"),
    }
    assert!(
        elapsed >= Duration::from_millis(2_500),
        "gave up too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(7),
        "took too long: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_concurrent_connections_demuxed() {
    const COUNT: u32 = 50;
    let mut listener = SrtListener::bind("127.0.0.1:0", SrtOptions::default())
        .await
        .expect("bind");
    let addr = listener.local_addr();

    let connect_a = SrtSocket::connect(addr, SrtOptions::default().streamid("conn-a"));
    let connect_b = SrtSocket::connect(addr, SrtOptions::default().streamid("conn-b"));
    let accept_two = async {
        let one = listener.accept().await.expect("accept 1").0;
        let two = listener.accept().await.expect("accept 2").0;
        (one, two)
    };
    let run = async {
        let (a, b, (one, two)) = tokio::join!(connect_a, connect_b, accept_two);
        let (a, b) = (a.expect("connect a"), b.expect("connect b"));
        // Map accepted sockets to their callers via streamid.
        let (for_a, for_b) = if one.streamid().as_deref() == Some("conn-a") {
            (one, two)
        } else {
            (two, one)
        };
        assert_eq!(for_a.streamid().as_deref(), Some("conn-a"));
        assert_eq!(for_b.streamid().as_deref(), Some("conn-b"));

        // Distinct payload streams must arrive on the right sockets.
        for i in 0 .. COUNT {
            a.send(&message(i, 300)).await.expect("send a");
            b.send(&message(1_000_000 + i, 300)).await.expect("send b");
        }
        a.close().await.expect("close a");
        b.close().await.expect("close b");

        for (mut sock, tag) in [(for_a, 0u32), (for_b, 1_000_000)] {
            let mut next = 0;
            while let Some(payload) = sock.recv().await.expect("recv") {
                assert_eq!(payload, message(tag + next, 300));
                next += 1;
            }
            assert_eq!(next, COUNT);
        }
    };
    tokio::time::timeout(Duration::from_secs(9), run)
        .await
        .expect("demux test timed out");
}

#[tokio::test]
async fn dropping_the_handle_closes_the_connection() {
    let (caller, mut accepted, _listener) =
        pair(SrtOptions::default(), SrtOptions::default()).await;
    drop(caller);
    // The caller driver senses the dropped handle, sends SHUTDOWN, and the
    // accepted side reaches a clean end of stream.
    let run = async {
        assert_eq!(accepted.recv().await.expect("recv"), None);
    };
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("accepted side never saw the close");
}
