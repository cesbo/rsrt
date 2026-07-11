//! Loopback integration tests: caller ↔ listener over 127.0.0.1 with real
//! tokio time. Each test finishes in a few seconds when run alone; the
//! outer timeouts are hang detectors sized to survive CPU starvation
//! under full parallel suite load, not performance assertions.

use std::{
    net::Ipv4Addr,
    time::{
        Duration,
        Instant,
    },
};

use rsrt::{
    CloseReason,
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

    // 600 ms latency is the ARQ recovery budget, not a delivery-delay
    // tuning knob: under parallel test load a task can stall long enough
    // for the kernel UDP buffer (silently clamped to rmem_max) to drop a
    // burst, and every NAK/retransmit round-trip must finish inside the
    // TSBPD window or the hole is TLPKTDROP'd. The lossy suites size this
    // 600-800 ms for the same reason.
    let copts = SrtOptions::default().latency(Duration::from_millis(600));
    // Generous UDP receive buffer on the listener socket (the receiving
    // side); the kernel clamps to rmem_max silently.
    let mut lopts = SrtOptions::default().latency(Duration::from_millis(600));
    lopts.udp_recv_buffer = Some(4 << 20);

    let (caller, mut accepted, _listener) = pair(copts, lopts).await;

    // Event-driven close: the receiver signals once all COUNT messages
    // have arrived and only then does the sender close. A fixed "ARQ
    // settle" sleep would orphan any tail hole still unrepaired when
    // SHUTDOWN tears the connection down.
    let (all_received_tx, all_received_rx) = tokio::sync::oneshot::channel::<()>();

    let send_task = tokio::spawn(async move {
        for i in 0 .. COUNT {
            caller.send(&message(i, LEN)).await.expect("send");
            // Light pacing keeps the loopback kernel buffer comfortable.
            if i % 25 == 24 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        all_received_rx.await.expect("receiver signal");
        caller.close().await.expect("close");
    });

    let recv_task = async {
        for next in 0 .. COUNT {
            let payload = accepted
                .recv()
                .await
                .expect("recv")
                .expect("stream ended early");
            assert_eq!(
                payload,
                message(next, LEN),
                "message {next} corrupted or out of order"
            );
        }
        all_received_tx.send(()).expect("send task gone");
        // Peer SHUTDOWN is a clean end of stream, not an error.
        assert_eq!(accepted.recv().await.expect("recv after close"), None);
    };
    // Hang detector, not a performance assertion: the test finishes in a
    // couple of seconds when run alone, but must survive multi-second
    // scheduling stalls under full parallel suite load.
    tokio::time::timeout(Duration::from_secs(30), recv_task)
        .await
        .expect("receive timed out");
    send_task.await.expect("send task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bidirectional_simultaneous() {
    const COUNT: u32 = 300;
    const LEN: usize = 700;
    // Flush sentinels: indexes at or above this tag are padding whose only
    // job is giving the peer's gap-driven NAK machinery a successor packet
    // that reveals (and so repairs) a lost tail of the real stream. They
    // sequence after the real messages, so in-order delivery of a repaired
    // tail is preserved; receivers stop after COUNT and never read them.
    const FLUSH_TAG: u32 = 0xF000_0000;

    // 600 ms latency as the ARQ recovery budget, same rationale as
    // unidirectional_2000_messages_in_order above.
    let copts = SrtOptions::default().latency(Duration::from_millis(600));
    let lopts = SrtOptions::default().latency(Duration::from_millis(600));
    let (caller, accepted, _listener) = pair(copts, lopts).await;

    // Both directions in flight at once; each task sends its stream, then
    // drains the opposite one (buffers hold COUNT messages comfortably).
    // Bursts stay small (10 packets ≈ 7.5 KB) because the loopback kernel
    // buffer is silently clamped to rmem_max and receives both directions'
    // bursts concurrently. Tail loss is the one hole NAKs cannot see, so
    // each side keeps emitting flush sentinels until the peer confirms it
    // received everything.
    async fn pump(
        mut sock: SrtSocket,
        tag: u32,
        done: tokio::sync::oneshot::Sender<()>,
        mut peer_done: tokio::sync::oneshot::Receiver<()>,
    ) -> SrtSocket {
        for i in 0 .. COUNT {
            sock.send(&message(tag.wrapping_add(i), LEN))
                .await
                .expect("send");
            if i % 10 == 9 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let want_tag: u32 = if tag == 0 { 1_000_000 } else { 0 };
        let mut flush = 0u32;
        for i in 0 .. COUNT {
            // recv() is cancel-safe, so a timed-out attempt loses nothing;
            // each quiet 25 ms interval sends one flush sentinel in case
            // the peer is stalled on a lost tail of *our* stream.
            let payload = loop {
                match tokio::time::timeout(Duration::from_millis(25), sock.recv()).await {
                    Ok(payload) => break payload.expect("recv").expect("unexpected EOF"),
                    Err(_) => {
                        sock.send(&message(FLUSH_TAG + flush, LEN))
                            .await
                            .expect("send flush");
                        flush += 1;
                    }
                }
            };
            assert_eq!(payload, message(want_tag.wrapping_add(i), LEN));
        }
        let _ = done.send(());
        // Keep the peer's repair path alive until it has everything too.
        loop {
            match tokio::time::timeout(Duration::from_millis(25), &mut peer_done).await {
                Ok(_) => break,
                Err(_) => {
                    sock.send(&message(FLUSH_TAG + flush, LEN))
                        .await
                        .expect("send flush");
                    flush += 1;
                }
            }
        }
        sock
    }

    let (caller_done_tx, caller_done_rx) = tokio::sync::oneshot::channel::<()>();
    let (accepted_done_tx, accepted_done_rx) = tokio::sync::oneshot::channel::<()>();
    let caller_side = tokio::spawn(pump(caller, 0, caller_done_tx, accepted_done_rx));
    let accepted_side = tokio::spawn(pump(accepted, 1_000_000, accepted_done_tx, caller_done_rx));
    let run = async {
        let caller = caller_side.await.expect("caller task");
        let accepted = accepted_side.await.expect("accepted task");
        caller.close().await.expect("caller close");
        accepted.close().await.expect("accepted close");
    };
    // Hang detector, not a performance assertion (see the module comment).
    tokio::time::timeout(Duration::from_secs(30), run)
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
    // Hang detector only. The tight give-up bound (connect_timeout + 1 s
    // harness margin, ~4 s) is enforced inside SrtSocket::connect
    // (src/socket.rs); a raw wall-clock bound here must additionally
    // absorb multi-second scheduling stalls of this current-thread
    // runtime under full parallel suite load, so keep it loose.
    assert!(
        elapsed < Duration::from_secs(30),
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

#[tokio::test]
async fn data_idle_closes_silent_caller() {
    // A 500 ms data-idle window on the caller, and nobody sends: the
    // drivers' automatic 1 s keepalives keep peer-idle quiet, so only the
    // data-idle window can close the connection. The caller's driver must
    // wake at the window deadline on its own (no traffic to prompt it),
    // and the accepted peer sees the close as a clean SHUTDOWN.
    let (mut caller, mut accepted, _listener) = pair(
        SrtOptions::default().data_idle_timeout(Duration::from_millis(500)),
        SrtOptions::default(),
    )
    .await;
    let run = async {
        let closed = caller.recv().await;
        assert!(
            matches!(closed, Err(SrtError::Closed(CloseReason::DataIdle))),
            "expected DataIdle close, got {closed:?}"
        );
        assert_eq!(accepted.recv().await.expect("peer recv"), None);
    };
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("data-idle close timed out");
}

#[tokio::test]
async fn data_idle_closes_silent_accepted_inherited_from_bind() {
    // The mirror direction, with the option set only at bind: the accepted
    // socket inherits it, breaks with DataIdle, and the silent caller sees
    // a clean SHUTDOWN.
    let (mut caller, mut accepted, _listener) = pair(
        SrtOptions::default(),
        SrtOptions::default().data_idle_timeout(Duration::from_millis(500)),
    )
    .await;
    let run = async {
        let closed = accepted.recv().await;
        assert!(
            matches!(closed, Err(SrtError::Closed(CloseReason::DataIdle))),
            "expected DataIdle close, got {closed:?}"
        );
        assert_eq!(caller.recv().await.expect("peer recv"), None);
    };
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("data-idle close timed out");
}
