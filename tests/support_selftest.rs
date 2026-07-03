//! Runs the test-support toolkit's own `#[cfg(test)]` tests.
//!
//! The toolkit lives in `tests/support/` and is pulled into each integration
//! test binary with `mod support;`. Integration tests are compiled with
//! `--test` (so `cfg(test)` is active) and the in-file self-tests below the
//! support modules register with this binary's harness. Run them with:
//!
//! ```sh
//! cargo test --test support_selftest
//! ```

mod support;

/// Cross-module smoke test: the pieces of the toolkit that interop tests
/// combine (port allocator + proxy + payload stream) work together.
#[tokio::test]
async fn toolkit_smoke() {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = support::LossyProxy::spawn(
        upstream.local_addr().unwrap(),
        support::ProxyBehavior::default(),
        42,
    )
    .await
    .unwrap();

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(proxy.local_addr()).await.unwrap();

    // Ship three deterministic 1316-byte messages through the proxy and
    // verify the reassembled byte stream.
    let mut generator = support::PayloadGen::new(7);
    let mut verifier = support::PayloadVerifier::new(7);
    let mut buf = vec![0u8; 2048];
    for _ in 0 .. 3 {
        client.send(&generator.next_message()).await.unwrap();
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            upstream.recv_from(&mut buf),
        )
        .await
        .expect("proxy did not forward")
        .unwrap();
        assert_eq!(len, support::MESSAGE_SIZE);
        verifier.update(&buf[.. len]).unwrap();
    }
    assert_eq!(verifier.verified(), 3 * support::MESSAGE_SIZE as u64);
    assert_eq!(proxy.stats().client_to_upstream.forwarded, 3);
    proxy.shutdown().await;
}
