//! Helpers for driving the reference `srt-live-transmit` binary (libsrt
//! 1.4.4) as an interop peer.
//!
//! `srt-live-transmit <input-uri> <output-uri>` moves a byte stream between
//! two URIs; the tests use `file://con` (stdin/stdout) on one side and an
//! `srt://` URI on the other. It re-chunks the stream into 1316-byte
//! messages (`SRTO_PAYLOADSIZE` default), which is why the payload verifier
//! in [`super::payload`] tolerates arbitrary re-chunking.
//!
//! Binary discovery: the `SRT_LIVE_TRANSMIT` environment variable (explicit
//! path) wins, then a `PATH` lookup. Tests that need the binary should start
//! with the [`require_slt!`] macro (or call [`find_binary`] themselves) so
//! machines without libsrt skip instead of fail.

use std::{
    path::{
        Path,
        PathBuf,
    },
    process::{
        ExitStatus,
        Stdio,
    },
    time::Duration,
};

use tokio::{
    io::{
        AsyncBufReadExt,
        AsyncReadExt,
        AsyncWriteExt,
        BufReader,
    },
    process::{
        Child,
        ChildStdin,
        ChildStdout,
        Command,
    },
    sync::mpsc,
    time::Instant,
};

/// Locates the `srt-live-transmit` binary.
///
/// Order: `$SRT_LIVE_TRANSMIT` (must point at an existing file), then each
/// entry of `$PATH`. Returns `None` when unavailable — tests should skip.
pub fn find_binary() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("SRT_LIVE_TRANSMIT") {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
        eprintln!(
            "SRT_LIVE_TRANSMIT is set but not a file: {}",
            path.display()
        );
        return None;
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("srt-live-transmit");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Resolves the binary or skips the current test:
///
/// ```ignore
/// let slt = support::require_slt!(); // returns PathBuf or returns from the test
/// ```
///
/// "Skip" is an early `return` with an eprintln marker (Rust's libtest has no
/// first-class skip); grep test output for `SKIP` to audit coverage.
macro_rules! require_slt {
    () => {
        match crate::support::slt::find_binary() {
            Some(path) => path,
            None => {
                eprintln!("SKIP: srt-live-transmit not found (PATH / $SRT_LIVE_TRANSMIT)");
                return;
            }
        }
    };
}
pub(crate) use require_slt;

/// Builds a caller-mode SRT URI: `srt://127.0.0.1:<port>?<params...>`.
///
/// `params` are raw `key=value` strings (e.g. `"latency=120"`).
pub fn caller_uri(port: u16, params: &[&str]) -> String {
    build_uri(&format!("srt://127.0.0.1:{port}"), params)
}

/// Builds a listener-mode SRT URI: `srt://:<port>?<params...>`.
/// (An empty host means listener mode for srt-live-transmit.)
pub fn listener_uri(port: u16, params: &[&str]) -> String {
    build_uri(&format!("srt://:{port}"), params)
}

fn build_uri(base: &str, params: &[&str]) -> String {
    if params.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", params.join("&"))
    }
}

/// A spawned `srt-live-transmit` (or any piped child) with:
/// - piped stdin/stdout handles (present per spawn mode),
/// - a background reader turning stderr into lines (also echoed to the test's stderr with a `[slt]`
///   prefix for debugging),
/// - kill-on-drop, so a panicking test never leaks the process.
pub struct SltProcess {
    child: Child,
    /// Piped stdin (send mode). `take()` it or use [`SltProcess::feed_stdin`].
    pub stdin: Option<ChildStdin>,
    /// Piped stdout (receive mode). `take()` it or use [`SltProcess::collect_stdout`].
    pub stdout: Option<ChildStdout>,
    stderr_lines: mpsc::UnboundedReceiver<String>,
}

impl SltProcess {
    /// Spawns a *sender*: reads the byte stream from stdin and transmits it
    /// over SRT. Equivalent to `srt-live-transmit <args> file://con <srt-uri>`.
    ///
    /// `extra_args` are inserted before the URIs (e.g. `["-ll:note"]`).
    pub fn spawn_send(binary: &Path, srt_uri: &str, extra_args: &[&str]) -> std::io::Result<Self> {
        let mut cmd = Command::new(binary);
        cmd.args(extra_args).arg("file://con").arg(srt_uri);
        Self::spawn_command(cmd, true, false)
    }

    /// Spawns a *receiver*: receives over SRT and writes the byte stream to
    /// stdout. Equivalent to `srt-live-transmit <args> <srt-uri> file://con`.
    pub fn spawn_receive(
        binary: &Path,
        srt_uri: &str,
        extra_args: &[&str],
    ) -> std::io::Result<Self> {
        let mut cmd = Command::new(binary);
        cmd.args(extra_args).arg(srt_uri).arg("file://con");
        Self::spawn_command(cmd, false, true)
    }

    /// Spawns an arbitrary command with the same plumbing (piped stderr line
    /// reader, kill-on-drop). Used internally and by self-tests.
    pub fn spawn_command(
        mut cmd: Command,
        pipe_stdin: bool,
        pipe_stdout: bool,
    ) -> std::io::Result<Self> {
        cmd.stdin(if pipe_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(if pipe_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::piped())
        .kill_on_drop(true);
        let mut child = cmd.spawn()?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take().expect("stderr was piped");
        let (tx, rx) = mpsc::unbounded_channel();
        let pid = child.id().unwrap_or(0);
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[slt {pid}] {line}");
                if tx.send(line).is_err() {
                    break; // receiver gone; keep draining? no — stop reading
                }
            }
        });

        Ok(SltProcess {
            child,
            stdin,
            stdout,
            stderr_lines: rx,
        })
    }

    /// OS process id (0 if already reaped).
    pub fn pid(&self) -> u32 {
        self.child.id().unwrap_or(0)
    }

    /// Writes `data` to the child's stdin in `chunk_size`-byte slices with
    /// `pace` sleep between slices (pace `ZERO` = as fast as the pipe
    /// accepts). Live mode needs pacing: srt-live-transmit forwards at input
    /// speed and a burst overruns latency/flow windows.
    ///
    /// Stdin stays open afterwards; call [`close_stdin`](Self::close_stdin)
    /// to signal end of stream.
    pub async fn feed_stdin(
        &mut self,
        data: &[u8],
        chunk_size: usize,
        pace: Duration,
    ) -> std::io::Result<()> {
        assert!(chunk_size > 0, "chunk_size must be non-zero");
        let stdin = self
            .stdin
            .as_mut()
            .expect("feed_stdin: stdin not piped or already taken/closed");
        for chunk in data.chunks(chunk_size) {
            stdin.write_all(chunk).await?;
            if !pace.is_zero() {
                tokio::time::sleep(pace).await;
            }
        }
        stdin.flush().await
    }

    /// Closes the child's stdin (EOF). srt-live-transmit exits shortly after.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Reads the child's stdout until `n` bytes were collected or `timeout`
    /// elapsed (whichever first) and returns whatever arrived — the caller
    /// asserts on the length. EOF also ends collection early.
    pub async fn collect_stdout(
        &mut self,
        n: usize,
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let stdout = self
            .stdout
            .as_mut()
            .expect("collect_stdout: stdout not piped or already taken");
        let deadline = Instant::now() + timeout;
        let mut collected = Vec::with_capacity(n);
        let mut buf = vec![0u8; 64 * 1024];
        while collected.len() < n {
            let left = (n - collected.len()).min(buf.len());
            match tokio::time::timeout_at(deadline, stdout.read(&mut buf[.. left])).await {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(len)) => collected.extend_from_slice(&buf[.. len]),
                Ok(Err(err)) => return Err(err),
                Err(_) => break, // timeout
            }
        }
        Ok(collected)
    }

    /// Next stderr log line, waiting up to `timeout`. `None` on timeout or
    /// when the process closed stderr and the backlog is drained.
    pub async fn next_stderr_line(&mut self, timeout: Duration) -> Option<String> {
        tokio::time::timeout(timeout, self.stderr_lines.recv())
            .await
            .ok()
            .flatten()
    }

    /// Waits (up to `timeout`) for a stderr line satisfying `pred`, returning
    /// it. Lines that don't match are consumed (they were already echoed).
    pub async fn wait_for_stderr<F>(&mut self, timeout: Duration, mut pred: F) -> Option<String>
    where
        F: FnMut(&str) -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            let line = self.next_stderr_line(left).await?;
            if pred(&line) {
                return Some(line);
            }
        }
    }

    /// Already-buffered stderr lines, without waiting.
    pub fn drain_stderr(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        while let Ok(line) = self.stderr_lines.try_recv() {
            lines.push(line);
        }
        lines
    }

    /// Kills the process and reaps it.
    pub async fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill().await
    }

    /// Waits for natural exit, up to `timeout`; kills on timeout and returns
    /// `None` (otherwise the exit status).
    pub async fn wait(&mut self, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
        // Dropping the write end first: srt-live-transmit in send mode only
        // exits once stdin reaches EOF.
        self.close_stdin();
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(status) => Ok(Some(status?)),
            Err(_) => {
                self.child.kill().await?;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_builders() {
        assert_eq!(caller_uri(4200, &[]), "srt://127.0.0.1:4200");
        assert_eq!(
            caller_uri(4200, &["latency=120", "streamid=abc"]),
            "srt://127.0.0.1:4200?latency=120&streamid=abc"
        );
        assert_eq!(listener_uri(4200, &[]), "srt://:4200");
        assert_eq!(
            listener_uri(4200, &["latency=60"]),
            "srt://:4200?latency=60"
        );
    }

    #[test]
    fn find_binary_does_not_panic() {
        // Result depends on the machine; only exercise both env branches.
        let _ = find_binary();
    }

    /// The piping plumbing works with any child process; `cat` echoes stdin
    /// to stdout, exercising feed_stdin + collect_stdout end to end.
    #[tokio::test]
    async fn feed_and_collect_roundtrip_via_cat() {
        let mut proc =
            SltProcess::spawn_command(Command::new("cat"), true, true).expect("spawn cat");
        let data: Vec<u8> = (0 .. 10_000u32).map(|i| (i % 251) as u8).collect();
        proc.feed_stdin(&data, 1316, Duration::ZERO).await.unwrap();
        proc.close_stdin();
        let out = proc
            .collect_stdout(data.len(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(out, data);
        let status = proc.wait(Duration::from_secs(5)).await.unwrap();
        assert!(status.expect("cat should exit").success());
    }

    /// Pacing actually spaces the writes out.
    #[tokio::test]
    async fn feed_stdin_paces() {
        let mut proc =
            SltProcess::spawn_command(Command::new("cat"), true, true).expect("spawn cat");
        let start = std::time::Instant::now();
        proc.feed_stdin(&[0u8; 40], 10, Duration::from_millis(20))
            .await
            .unwrap();
        assert!(
            start.elapsed() >= Duration::from_millis(60),
            "4 chunks, 20 ms pace"
        );
        proc.kill().await.unwrap();
    }

    /// collect_stdout returns the partial read on timeout instead of hanging.
    #[tokio::test]
    async fn collect_stdout_times_out_with_partial_data() {
        let mut proc =
            SltProcess::spawn_command(Command::new("cat"), true, true).expect("spawn cat");
        proc.feed_stdin(b"hello", 5, Duration::ZERO).await.unwrap();
        // Ask for more than will ever arrive; stdin stays open so no EOF.
        let out = proc
            .collect_stdout(1000, Duration::from_millis(300))
            .await
            .unwrap();
        assert_eq!(out, b"hello");
        proc.kill().await.unwrap();
    }

    /// The stderr line reader delivers lines in order and detects patterns.
    #[tokio::test]
    async fn stderr_line_reader() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("echo one >&2; echo two >&2; echo 'SRT source connected' >&2");
        let mut proc = SltProcess::spawn_command(cmd, false, false).expect("spawn sh");
        assert_eq!(
            proc.next_stderr_line(Duration::from_secs(2))
                .await
                .as_deref(),
            Some("one")
        );
        let hit = proc
            .wait_for_stderr(Duration::from_secs(2), |l| l.contains("connected"))
            .await;
        assert_eq!(hit.as_deref(), Some("SRT source connected"));
        let status = proc.wait(Duration::from_secs(2)).await.unwrap();
        assert!(status.expect("sh should exit").success());
    }

    /// If srt-live-transmit is installed: spawn a listener-receiver on a free
    /// port, make sure it starts (process alive) and dies cleanly on kill.
    /// This is the deepest self-test possible without a working SRT peer.
    #[tokio::test]
    async fn spawn_real_binary_listener_and_kill() {
        let binary = require_slt!();
        let port = crate::support::net::free_udp_port().unwrap();
        let mut proc = SltProcess::spawn_receive(
            &binary,
            &listener_uri(port, &["latency=120"]),
            &["-ll:note"],
        )
        .expect("spawn srt-live-transmit");
        // Give it a moment to bind; it must still be running (a bad CLI would
        // exit immediately with an error).
        tokio::time::sleep(Duration::from_millis(500)).await;
        let exited = proc.child.try_wait().expect("try_wait");
        assert!(
            exited.is_none(),
            "srt-live-transmit exited early: {exited:?}, stderr: {:?}",
            proc.drain_stderr()
        );
        proc.kill().await.unwrap();
    }
}
