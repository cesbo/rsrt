//! Send a file (or stdin) over SRT at a steady bitrate.
//!
//! ```text
//! send <input-file|-> <srt-url>
//!
//! srt://host:port      connect to host:port and push the stream (caller)
//! srt://:port          listen on port, accept one receiver (listener)
//! srt://0.0.0.0:port   same as srt://:port
//!
//! Query parameters:
//!   ?rate=<mbps>       target bitrate, Mbit/s of payload (default 4)
//!   ?latency=<ms>      TSBPD latency, milliseconds (default 120)
//!   ?streamid=<s>      StreamID to announce when calling (ignored when listening)
//!   ?passphrase=<pw>   enable AES encryption, 10..80 characters (default off)
//!   ?pbkeylen=<n>      AES key length, bytes: 16, 24 or 32 (default 16)
//! ```
//!
//! Reads 1316-byte chunks (7 MPEG-TS packets — one SRT live payload, the
//! srt-live-transmit default) and paces them with a `tokio::time::interval`.
//! A stats line goes to stderr every 2 s; the stream is closed cleanly at
//! end of input.
//!
//! Try it against `examples/recv.rs`:
//!
//! ```text
//! cargo run --example recv -- 'srt://:9000' out.ts
//! cargo run --example send -- in.ts 'srt://127.0.0.1:9000?rate=8'
//! ```

mod common;

use std::{
    error::Error,
    fs,
    future::Future,
    io::{
        self,
        Read,
    },
    thread,
    time::Duration,
};

use rsrt::{
    KeyLength,
    SrtListener,
    SrtOptions,
    SrtSocket,
    Stats,
};
use tokio::{
    sync::mpsc,
    time::{
        interval,
        sleep,
        sleep_until,
        Instant,
        MissedTickBehavior,
    },
};

use self::common::SrtUrl;

/// One SRT live payload: 7 × 188-byte MPEG-TS packets (SRTO_PAYLOADSIZE
/// default in srt-live-transmit); well under the 1456-byte live maximum.
const CHUNK: usize = 1316;
const DEFAULT_RATE_MBPS: f64 = 4.0;
const STATS_PERIOD: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let input = args.next().unwrap_or_else(|| usage());
    let url = args.next().unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }

    let url = SrtUrl::parse(&url)?;
    let mut opts = SrtOptions::default();
    let mut rate_mbps = DEFAULT_RATE_MBPS;
    for (key, value) in url.params() {
        match key.as_str() {
            "rate" => {
                rate_mbps = value
                    .parse()
                    .ok()
                    .filter(|r: &f64| r.is_finite() && *r > 0.0)
                    .ok_or_else(|| format!("invalid rate {value:?}"))?;
            }
            "latency" => {
                let ms: u64 = value
                    .parse()
                    .map_err(|_| format!("invalid latency {value:?}"))?;
                // Both directions, like srt-live-transmit's `latency=`
                // (SRTO_LATENCY sets SRTO_RCVLATENCY and SRTO_PEERLATENCY).
                opts.latency = Duration::from_millis(ms);
                opts.peer_latency = Duration::from_millis(ms);
            }
            "streamid" => opts.streamid = Some(value.clone()),
            // Length is validated by connect/bind (10..80 bytes).
            "passphrase" => opts.passphrase = Some(value.clone().into()),
            "pbkeylen" => {
                // Bytes, like SRTO_PBKEYLEN: 16, 24 or 32.
                let n: usize = value
                    .parse()
                    .map_err(|_| format!("invalid pbkeylen {value:?}"))?;
                let len = KeyLength::from_bytes(n)
                    .ok_or_else(|| format!("pbkeylen must be 16, 24 or 32, got {value:?}"))?;
                opts.pbkeylen = Some(len);
            }
            other => eprintln!("send: ignoring unknown parameter {other:?}"),
        }
    }
    // After the last chunk, give ARQ one latency's worth of time to recover
    // tail losses before SHUTDOWN makes them permanent.
    let linger = opts.latency + Duration::from_millis(100);

    let mut chunks = spawn_reader(&input)?;
    let sock = open(&url, opts).await?;

    let period = chunk_period(rate_mbps);
    eprintln!(
        "send: pacing {CHUNK}-byte chunks every {}us (~{rate_mbps} Mbit/s)",
        period.as_micros(),
    );
    let mut pace = interval(period);
    // After a stall (slow stdin), resume at the steady rate; never burst.
    pace.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut next_stats = Instant::now() + STATS_PERIOD;
    let mut total = 0u64;
    loop {
        let chunk = match with_stats(&sock, &mut next_stats, chunks.recv()).await {
            Some(Ok(chunk)) => chunk,
            Some(Err(e)) => return Err(format!("read error: {e}").into()),
            None => break, // end of input
        };
        with_stats(&sock, &mut next_stats, pace.tick()).await;
        sock.send(&chunk).await?;
        total += chunk.len() as u64;
    }

    eprintln!("send: end of input, {total} bytes sent");
    with_stats(&sock, &mut next_stats, sleep(linger)).await;
    print_stats(&sock.stats());
    sock.close().await?;
    Ok(())
}

/// Awaits `f` while keeping the stats cadence: whenever the deadline passes
/// before `f` completes, a stats line is printed and the wait resumes.
async fn with_stats<F: Future>(sock: &SrtSocket, next_stats: &mut Instant, f: F) -> F::Output {
    tokio::pin!(f);
    loop {
        tokio::select! {
            out = &mut f => return out,
            _ = sleep_until(*next_stats) => {
                print_stats(&sock.stats());
                *next_stats = Instant::now() + STATS_PERIOD;
            }
        }
    }
}

/// Connects or listens according to the URL (see [`SrtUrl::is_listener`]).
async fn open(url: &SrtUrl, opts: SrtOptions) -> Result<SrtSocket, Box<dyn Error>> {
    if url.is_listener() {
        let mut listener = SrtListener::bind(url.socket_addr(), opts).await?;
        eprintln!("send: listening on {}", listener.local_addr());
        let (sock, peer) = listener.accept().await?;
        eprintln!("send: accepted {peer}");
        Ok(sock)
    } else {
        let sock = SrtSocket::connect(url.socket_addr(), opts).await?;
        eprintln!("send: connected to {}", sock.peer_addr());
        Ok(sock)
    }
}

/// Interval between chunks for the target payload bitrate.
fn chunk_period(rate_mbps: f64) -> Duration {
    Duration::from_secs_f64((CHUNK * 8) as f64 / (rate_mbps * 1_000_000.0))
}

/// Spawns the blocking input thread: file/stdin reads never stall the async
/// runtime, and the bounded queue keeps only a few chunks ahead of the pacer.
fn spawn_reader(path: &str) -> io::Result<mpsc::Receiver<io::Result<Vec<u8>>>> {
    let mut input: Box<dyn Read + Send> = if path == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(fs::File::open(path)?)
    };
    let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>(16);
    thread::spawn(move || {
        let mut buf = [0u8; CHUNK];
        loop {
            let chunk = match read_chunk(&mut *input, &mut buf) {
                Ok(0) => break,
                Ok(n) => Ok(buf[.. n].to_vec()),
                Err(e) => {
                    let _ = tx.blocking_send(Err(e));
                    break;
                }
            };
            if tx.blocking_send(chunk).is_err() {
                break; // main exited
            }
        }
    });
    Ok(rx)
}

/// Fills `buf` as far as the input allows (pipes deliver short reads);
/// returns the bytes gathered — 0 only at end of input.
fn read_chunk(input: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled ..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn print_stats(s: &Stats) {
    eprintln!(
        "send: pkts={} bytes={} dropped={} retrans={} rtt={:.3}ms",
        s.pkts_sent,
        s.bytes_sent,
        s.pkts_send_dropped,
        s.pkts_retransmitted,
        s.rtt_us as f64 / 1000.0,
    );
}

fn usage() -> ! {
    eprintln!("usage: send <input-file|-> <srt-url>");
    eprintln!("  srt://host:port[?rate=<mbps>][&latency=<ms>][&streamid=<s>]  connect (caller)");
    eprintln!("  srt://:port  or  srt://0.0.0.0:port                          listen, accept one");
    eprintln!("  encryption:  [&passphrase=<pw>][&pbkeylen=<16|24|32>]");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_period_matches_rate() {
        // 1316 bytes at 4 Mbit/s -> 2632 us per chunk.
        assert_eq!(chunk_period(4.0).as_micros(), 2632);
        // Doubling the rate halves the period.
        assert_eq!(chunk_period(8.0).as_micros(), 1316);
    }

    /// A reader that delivers one byte at a time: `read_chunk` must still
    /// assemble full chunks (pipes routinely return short reads).
    struct Trickle(Vec<u8>, usize);

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.1 >= self.0.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.0[self.1];
            self.1 += 1;
            Ok(1)
        }
    }

    #[test]
    fn read_chunk_assembles_short_reads() {
        let data: Vec<u8> = (0 .. CHUNK as u32 + 10).map(|i| i as u8).collect();
        let mut input = Trickle(data.clone(), 0);
        let mut buf = [0u8; CHUNK];
        // First chunk fills completely despite 1-byte reads.
        assert_eq!(read_chunk(&mut input, &mut buf).unwrap(), CHUNK);
        assert_eq!(&buf[..], &data[.. CHUNK]);
        // The tail is a short final chunk, then a clean EOF.
        assert_eq!(read_chunk(&mut input, &mut buf).unwrap(), 10);
        assert_eq!(&buf[.. 10], &data[CHUNK ..]);
        assert_eq!(read_chunk(&mut input, &mut buf).unwrap(), 0);
    }

    #[test]
    fn reader_thread_streams_file_in_chunks() {
        let dir = std::env::temp_dir().join(format!("srt-send-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("in.bin");
        let data: Vec<u8> = (0 .. CHUNK * 2 + 5).map(|i| i as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let mut rx = spawn_reader(path.to_str().unwrap()).unwrap();
        let mut got = Vec::new();
        while let Some(chunk) = rx.blocking_recv() {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= CHUNK);
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, data);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spawn_reader_missing_file_errors() {
        assert!(spawn_reader("/nonexistent/definitely-missing").is_err());
    }
}
