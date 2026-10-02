//! Receive an SRT stream and write its payloads to a file or stdout.
//!
//! ```text
//! recv <srt-url> [output-file]
//!
//! srt://host:port      connect to host:port and pull the stream (caller)
//! srt://:port          listen on port, accept one sender (listener)
//! srt://0.0.0.0:port   same as srt://:port
//!
//! Query parameters:
//!   ?latency=<ms>      TSBPD latency, milliseconds (default 120)
//!   ?streamid=<s>      StreamID to announce when calling (ignored when listening)
//!   ?passphrase=<pw>   enable AES encryption, 10..80 characters (default off)
//!   ?pbkeylen=<n>      AES key length, bytes: 16, 24 or 32 (default 16)
//! ```
//!
//! Payloads go to `output-file` (stdout if omitted); a stats line goes to
//! stderr every 2 s. Exits cleanly when the sender shuts the stream down.
//!
//! Try it against `examples/send.rs`:
//!
//! ```text
//! cargo run --example recv -- 'srt://:9000' out.ts
//! cargo run --example send -- in.ts 'srt://127.0.0.1:9000'
//! ```

mod common;

use std::{
    error::Error,
    fs,
    io::{
        self,
        BufWriter,
        Write,
    },
    thread,
    time::Duration,
};

use rsrt::{
    Bytes,
    KeyLength,
    SrtListener,
    SrtOptions,
    SrtSocket,
    Stats,
};
use tokio::{
    sync::mpsc,
    time::{
        timeout_at,
        Instant,
    },
};

use self::common::SrtUrl;

const STATS_PERIOD: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let url = args.next().unwrap_or_else(|| usage());
    let output = args.next();
    if args.next().is_some() {
        usage();
    }

    let url = SrtUrl::parse(&url)?;
    let mut opts = SrtOptions::default();
    for (key, value) in url.params() {
        match key.as_str() {
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
            other => eprintln!("recv: ignoring unknown parameter {other:?}"),
        }
    }

    let (payload_tx, writer) = spawn_writer(output)?;
    let mut sock = open(&url, opts).await?;

    let mut next_stats = Instant::now() + STATS_PERIOD;
    let mut total = 0u64;
    let mut stream_result = Ok(());
    loop {
        // recv() is cancel-safe, so the stats deadline can cut it short
        // without losing a message.
        match timeout_at(next_stats, sock.recv()).await {
            Ok(Ok(Some(payload))) => {
                total += payload.len() as u64;
                if payload_tx.send(payload).await.is_err() {
                    break; // writer failed; its error is picked up below
                }
                // `timeout_at` polls recv() first, so a saturated stream
                // would starve the deadline arm — keep the cadence by hand.
                if Instant::now() >= next_stats {
                    print_stats(&sock.stats());
                    next_stats = Instant::now() + STATS_PERIOD;
                }
            }
            Ok(Ok(None)) => {
                eprintln!("recv: end of stream");
                break;
            }
            Ok(Err(e)) => {
                stream_result = Err(e);
                break;
            }
            Err(_deadline) => {
                print_stats(&sock.stats());
                next_stats = Instant::now() + STATS_PERIOD;
            }
        }
    }

    print_stats(&sock.stats());
    sock.close().await?;
    drop(payload_tx); // ends the writer's queue -> flush + thread exit
    writer.join().map_err(|_| "writer thread panicked")??;
    stream_result?;
    eprintln!("recv: done, {total} bytes written");
    Ok(())
}

/// Connects or listens according to the URL (see [`SrtUrl::is_listener`]).
async fn open(url: &SrtUrl, opts: SrtOptions) -> Result<SrtSocket, Box<dyn Error>> {
    if url.is_listener() {
        let mut listener = SrtListener::bind(url.socket_addr(), opts).await?;
        eprintln!("recv: listening on {}", listener.local_addr());
        let (sock, peer) = listener.accept().await?;
        match sock.streamid() {
            Some(sid) => eprintln!("recv: accepted {peer} (streamid {sid:?})"),
            None => eprintln!("recv: accepted {peer}"),
        }
        Ok(sock)
    } else {
        let sock = SrtSocket::connect(url.socket_addr(), opts).await?;
        eprintln!("recv: connected to {}", sock.peer_addr());
        Ok(sock)
    }
}

/// Queue handle plus join handle for the blocking output thread.
type Writer = (mpsc::Sender<Bytes>, thread::JoinHandle<io::Result<()>>);

/// Spawns the blocking output thread: file/stdout writes never stall the
/// async runtime, and the bounded queue applies backpressure to `recv`
/// instead of buffering without limit.
fn spawn_writer(path: Option<String>) -> io::Result<Writer> {
    let out: Box<dyn Write + Send> = match &path {
        Some(path) => Box::new(fs::File::create(path)?),
        None => Box::new(io::stdout()),
    };
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);
    let writer = thread::spawn(move || -> io::Result<()> {
        let mut out = BufWriter::new(out);
        while let Some(payload) = rx.blocking_recv() {
            out.write_all(&payload)?;
        }
        out.flush()
    });
    Ok((tx, writer))
}

fn print_stats(s: &Stats) {
    eprintln!(
        "recv: pkts={} bytes={} lost={} dropped={} retrans={} rtt={:.3}ms drift={:.3}ms",
        s.pkts_recv,
        s.bytes_recv,
        s.pkts_recv_lost,
        s.pkts_recv_dropped,
        s.pkts_retransmitted,
        s.rtt_us as f64 / 1000.0,
        s.tsbpd_drift_us as f64 / 1000.0,
    );
}

fn usage() -> ! {
    eprintln!("usage: recv <srt-url> [output-file]");
    eprintln!("  srt://host:port[?latency=<ms>][&streamid=<s>]   connect (caller)");
    eprintln!("  srt://:port  or  srt://0.0.0.0:port             listen, accept one");
    eprintln!("  encryption:  [&passphrase=<pw>][&pbkeylen=<16|24|32>]");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_thread_writes_and_flushes() {
        let dir = std::env::temp_dir().join(format!("srt-recv-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.bin");
        let (tx, writer) = spawn_writer(Some(path.to_str().unwrap().to_string())).unwrap();
        tx.blocking_send(Bytes::from_static(b"hello ")).unwrap();
        tx.blocking_send(Bytes::from_static(b"world")).unwrap();
        drop(tx);
        writer.join().unwrap().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello world");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
