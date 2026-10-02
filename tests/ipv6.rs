//! IPv6 caller/listener integration, including encryption and source binding.

#[allow(dead_code)]
#[path = "support/net.rs"]
mod net_support;

use std::{
    net::{
        Ipv4Addr,
        Ipv6Addr,
        SocketAddr,
        SocketAddrV4,
        SocketAddrV6,
    },
    time::Duration,
};

use rsrt::{
    SrtError,
    SrtListener,
    SrtOptions,
    SrtSocket,
};

async fn pair(
    caller_opts: SrtOptions,
    listener_opts: SrtOptions,
) -> (
    SrtSocket<SocketAddr>,
    SrtSocket<SocketAddr>,
    SrtListener<SocketAddr>,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut listener = SrtListener::bind_ip("[::1]:0", listener_opts)
            .await
            .unwrap();
        let addr = listener.local_addr();
        assert!(addr.is_ipv6());
        let (caller, accepted) =
            tokio::join!(SrtSocket::connect_ip(addr, caller_opts), listener.accept(),);
        let caller = caller.unwrap();
        let (accepted, peer) = accepted.unwrap();
        assert_eq!(peer.ip(), Ipv6Addr::LOCALHOST);
        assert_ne!(peer.port(), 0);
        assert_eq!(accepted.peer_addr(), peer);
        assert_eq!(caller.peer_addr(), addr);
        (caller, accepted, listener)
    })
    .await
    .expect("IPv6 handshake timed out")
}

async fn exchange(opts: SrtOptions) {
    let (mut caller, mut accepted, _listener) = pair(opts.clone(), opts).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        // Exercises both the connected and listener-demux send paths,
        // including vectored data sends on Unix.
        for i in 0 .. 16u8 {
            let forward = vec![i; 1316];
            let reverse = vec![255 - i; 1316];
            caller.send(&forward).await.unwrap();
            accepted.send(&reverse).await.unwrap();
            assert_eq!(accepted.recv().await.unwrap().unwrap().as_ref(), forward);
            assert_eq!(caller.recv().await.unwrap().unwrap().as_ref(), reverse);
        }
        assert_eq!(caller.stats().undecrypted_pkts, 0);
        assert_eq!(accepted.stats().undecrypted_pkts, 0);
        caller.close().await.unwrap();
        accepted.close().await.unwrap();
    })
    .await
    .expect("IPv6 transfer timed out");
}

#[tokio::test]
async fn ipv6_bidirectional_transfer() {
    exchange(SrtOptions::default()).await;
}

#[tokio::test]
async fn ipv6_encrypted_bidirectional_transfer() {
    exchange(SrtOptions::default().passphrase("ipv6 shared secret")).await;
}

#[tokio::test]
async fn ipv6_source_binding_and_streamid() {
    let port = net_support::free_udp_port_v6().unwrap();
    let opts = SrtOptions::default()
        .local_addr_v6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
        .streamid("ipv6-stream");
    let (caller, accepted, _listener) = pair(opts, SrtOptions::default()).await;
    assert_eq!(accepted.streamid().as_deref(), Some("ipv6-stream"));
    assert_eq!(accepted.peer_addr().ip(), Ipv6Addr::LOCALHOST);
    assert_eq!(accepted.peer_addr().port(), port);
    caller.close().await.unwrap();
    accepted.close().await.unwrap();
}

#[tokio::test]
async fn ipv6_send_limit_uses_negotiated_mss() {
    let (mut caller, mut accepted, _listener) = pair(
        SrtOptions::default(),
        SrtOptions {
            mss: 1360,
            ..SrtOptions::default()
        },
    )
    .await;
    // SRT uses a fixed 44-byte MSS allowance for either family, matching libsrt.
    for socket in [&caller, &accepted] {
        assert!(matches!(
            socket.send(&[0; 1317]).await,
            Err(SrtError::PayloadTooLarge(1317))
        ));
    }
    caller.send(&[42; 1316]).await.unwrap();
    let payload = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(payload.as_ref(), &[42; 1316]);
    accepted.send(&[43; 1316]).await.unwrap();
    let payload = tokio::time::timeout(Duration::from_secs(5), caller.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(payload.as_ref(), &[43; 1316]);
    caller.close().await.unwrap();
    accepted.close().await.unwrap();
}

#[tokio::test]
async fn source_family_mismatch_fails_before_handshake() {
    for (target, opts) in [
        (
            "[::1]:9000",
            SrtOptions::default().local_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        ),
        (
            "127.0.0.1:9000",
            SrtOptions::default().local_addr_v6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)),
        ),
    ] {
        match SrtSocket::connect_ip(target, opts).await {
            Err(SrtError::Io(err)) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput),
            _ => panic!("expected a source/target family error"),
        }
    }
    let opts = SrtOptions {
        local_addr: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        local_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)),
        ..SrtOptions::default()
    };
    assert!(matches!(
        SrtSocket::connect_ip("[::1]:9000", opts).await,
        Err(SrtError::Io(_))
    ));
}

#[tokio::test]
async fn ipv6_listener_demuxes_multiple_callers() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut listener = SrtListener::bind_ip("[::1]:0", SrtOptions::default())
            .await
            .unwrap();
        let addr = listener.local_addr();
        let (first, second, peers) = tokio::join!(
            SrtSocket::connect_ip(addr, SrtOptions::default().streamid("first")),
            SrtSocket::connect_ip(addr, SrtOptions::default().streamid("second")),
            async {
                (
                    listener.accept().await.unwrap(),
                    listener.accept().await.unwrap(),
                )
            },
        );
        let first = first.unwrap();
        let second = second.unwrap();
        first.send(b"first").await.unwrap();
        second.send(b"second").await.unwrap();
        for (mut socket, peer) in [peers.0, peers.1] {
            assert_eq!(socket.peer_addr(), peer);
            let id = socket.streamid().unwrap();
            assert_eq!(
                socket.recv().await.unwrap().unwrap().as_ref(),
                id.as_bytes()
            );
            socket.close().await.unwrap();
        }
        first.close().await.unwrap();
        second.close().await.unwrap();
    })
    .await
    .expect("IPv6 demux timed out");
}

#[tokio::test]
async fn existing_ipv4_types_and_ip_apis_interoperate() {
    // These annotations pin the existing API contracts at compile time.
    let mut listener: SrtListener = SrtListener::bind("127.0.0.1:0", SrtOptions::default())
        .await
        .unwrap();
    let addr: SocketAddrV4 = listener.local_addr();
    let (caller, accepted) = tokio::join!(
        SrtSocket::connect_ip(addr, SrtOptions::default()),
        listener.accept()
    );
    let caller: SrtSocket<SocketAddr> = caller.unwrap();
    let (accepted, peer): (SrtSocket, SocketAddrV4) = accepted.unwrap();
    let _: SocketAddrV4 = accepted.peer_addr();
    assert_eq!(SocketAddr::from(peer), accepted.peer_addr().into());
    assert_eq!(caller.peer_addr(), SocketAddr::from(addr));
    caller.close().await.unwrap();
    accepted.close().await.unwrap();

    let mut listener = SrtListener::bind_ip("127.0.0.1:0", SrtOptions::default())
        .await
        .unwrap();
    let (caller, accepted) = tokio::join!(
        SrtSocket::connect(listener.local_addr(), SrtOptions::default()),
        listener.accept()
    );
    let caller: SrtSocket = caller.unwrap();
    let (accepted, _) = accepted.unwrap();
    assert_eq!(SocketAddr::from(caller.peer_addr()), listener.local_addr());
    caller.close().await.unwrap();
    accepted.close().await.unwrap();
}
