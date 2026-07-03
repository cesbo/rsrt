//! Deterministic test payloads.
//!
//! A payload *stream* is an infinite pseudo-random byte sequence fully
//! determined by a seed (see [`SplitMix64::fill`] for the exact byte layout).
//! The generator hands it out in 1316-byte messages — the MPEG-TS-friendly
//! chunk size `srt-live-transmit` uses (7 × 188) — and the verifier checks a
//! received byte stream against the same seed *independently of chunking*,
//! because `srt-live-transmit` re-chunks its input at 1316 bytes and pipes
//! merge writes arbitrarily.

use std::fmt;

use super::rng::SplitMix64;

/// Live-mode message size used by `srt-live-transmit`: 7 MPEG-TS packets.
pub const MESSAGE_SIZE: usize = 1316;

/// Produces the deterministic byte stream for a seed, chunked into
/// [`MESSAGE_SIZE`]-byte messages.
///
/// Byte `i` of the stream depends only on `(seed, i)`; concatenating the
/// emitted chunks always reproduces the same stream.
pub struct PayloadGen {
    rng: SplitMix64,
    /// Bytes handed out so far. Kept word-aligned internally by construction:
    /// all output goes through `next_bytes`, which buffers partial words.
    produced: u64,
    /// Unconsumed tail of the last PRNG word (`next_bytes` leftovers).
    word: [u8; 8],
    word_pos: usize,
}

impl PayloadGen {
    pub fn new(seed: u64) -> Self {
        PayloadGen {
            rng: SplitMix64::new(seed),
            produced: 0,
            word: [0; 8],
            word_pos: 8,
        }
    }

    /// Total bytes generated so far.
    pub fn produced(&self) -> u64 {
        self.produced
    }

    /// Next [`MESSAGE_SIZE`]-byte message of the stream.
    pub fn next_message(&mut self) -> Vec<u8> {
        self.next_bytes(MESSAGE_SIZE)
    }

    /// Next `len` bytes of the stream (any chunking yields the same stream).
    pub fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            if self.word_pos == 8 {
                self.word = self.rng.next_u64().to_le_bytes();
                self.word_pos = 0;
            }
            let take = (len - out.len()).min(8 - self.word_pos);
            out.extend_from_slice(&self.word[self.word_pos .. self.word_pos + take]);
            self.word_pos += take;
        }
        self.produced += len as u64;
        out
    }

    /// Convenience: the first `len` bytes of the stream for `seed`.
    pub fn stream_prefix(seed: u64, len: usize) -> Vec<u8> {
        PayloadGen::new(seed).next_bytes(len)
    }
}

/// First point where a received stream diverges from the expected one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadMismatch {
    /// Byte offset into the stream (counting from 0 at the stream start).
    pub offset: u64,
    pub expected: u8,
    pub actual: u8,
}

impl fmt::Display for PayloadMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "payload mismatch at offset {}: expected {:#04x}, got {:#04x}",
            self.offset, self.expected, self.actual
        )
    }
}

impl std::error::Error for PayloadMismatch {}

/// Incremental verifier: feed received bytes in any chunking; it checks them
/// against the expected stream for the seed, byte by byte.
///
/// A clean SRT live transfer preserves the byte stream even though message
/// boundaries move (1316-byte re-chunking, pipe buffering), so "received data
/// is a prefix of the expected stream" is the correctness criterion. Loss
/// without retransmission shows up as a mismatch at the gap.
pub struct PayloadVerifier {
    expected: PayloadGen,
    verified: u64,
    /// First mismatch seen; once set, every further `update` re-reports it
    /// (the forward-only PRNG cannot resynchronize past a fault anyway).
    poisoned: Option<PayloadMismatch>,
}

impl PayloadVerifier {
    pub fn new(seed: u64) -> Self {
        PayloadVerifier {
            expected: PayloadGen::new(seed),
            verified: 0,
            poisoned: None,
        }
    }

    /// Bytes verified so far (== total bytes fed if no error was returned).
    pub fn verified(&self) -> u64 {
        self.verified
    }

    /// Checks the next received bytes. On mismatch reports the *stream*
    /// offset of the first bad byte; the verifier is poisoned afterwards
    /// (further updates keep failing with the same mismatch).
    pub fn update(&mut self, received: &[u8]) -> Result<(), PayloadMismatch> {
        if let Some(err) = self.poisoned {
            return Err(err);
        }
        let expected = self.expected.next_bytes(received.len());
        for (i, (&actual, &want)) in received.iter().zip(expected.iter()).enumerate() {
            if actual != want {
                let err = PayloadMismatch {
                    offset: self.verified + i as u64,
                    expected: want,
                    actual,
                };
                self.poisoned = Some(err);
                return Err(err);
            }
        }
        self.verified += received.len() as u64;
        Ok(())
    }
}

/// One-shot check that `received` equals the first `received.len()` bytes of
/// the stream for `seed`.
pub fn verify_prefix(seed: u64, received: &[u8]) -> Result<(), PayloadMismatch> {
    PayloadVerifier::new(seed).update(received)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_is_1316_bytes() {
        let mut generator = PayloadGen::new(1);
        assert_eq!(generator.next_message().len(), MESSAGE_SIZE);
        assert_eq!(generator.produced(), MESSAGE_SIZE as u64);
    }

    #[test]
    fn stream_is_chunking_independent() {
        let whole = PayloadGen::stream_prefix(99, 5000);

        // Same stream drawn as messages...
        let mut generator = PayloadGen::new(99);
        let mut by_message = Vec::new();
        while by_message.len() < 5000 {
            by_message.extend_from_slice(&generator.next_message());
        }
        assert_eq!(&by_message[.. 5000], &whole[..]);

        // ...and as awkward odd-sized reads.
        let mut generator = PayloadGen::new(99);
        let mut odd = Vec::new();
        for len in [1, 7, 188, 3, 1316, 999, 1500, 986] {
            odd.extend_from_slice(&generator.next_bytes(len));
        }
        assert_eq!(odd.len(), 5000);
        assert_eq!(odd, whole);
    }

    #[test]
    fn distinct_seeds_distinct_streams() {
        assert_ne!(
            PayloadGen::stream_prefix(1, 64),
            PayloadGen::stream_prefix(2, 64)
        );
    }

    #[test]
    fn verifier_accepts_rechunked_stream() {
        let data = PayloadGen::stream_prefix(7, 4321);
        let mut verifier = PayloadVerifier::new(7);
        // Feed with chunk sizes unrelated to how it was generated.
        let mut pos = 0;
        for len in [100, 1, 1316, 1316, 500, 1088] {
            verifier.update(&data[pos .. pos + len]).unwrap();
            pos += len;
        }
        assert_eq!(pos, data.len());
        assert_eq!(verifier.verified(), 4321);
    }

    #[test]
    fn verifier_catches_corruption_at_exact_offset() {
        let mut data = PayloadGen::stream_prefix(7, 3000);
        data[2500] ^= 0x01;

        let mut verifier = PayloadVerifier::new(7);
        verifier.update(&data[.. 2000]).unwrap();
        let err = verifier.update(&data[2000 ..]).unwrap_err();
        assert_eq!(err.offset, 2500);
        assert_eq!(err.actual, err.expected ^ 0x01);
    }

    #[test]
    fn verifier_catches_missing_chunk() {
        // Drop 1316 bytes in the middle — mimics an unrecovered loss.
        let data = PayloadGen::stream_prefix(7, 4 * MESSAGE_SIZE);
        let mut verifier = PayloadVerifier::new(7);
        verifier.update(&data[.. MESSAGE_SIZE]).unwrap();
        let err = verifier
            .update(&data[2 * MESSAGE_SIZE .. 3 * MESSAGE_SIZE])
            .unwrap_err();
        // The gap is detected somewhere at/after the splice point; with
        // pseudo-random data the very first byte differs almost surely.
        assert_eq!(err.offset, MESSAGE_SIZE as u64);
    }

    #[test]
    fn verifier_stays_poisoned_after_mismatch() {
        let mut data = PayloadGen::stream_prefix(5, 100);
        data[10] ^= 0xFF;
        let mut verifier = PayloadVerifier::new(5);
        let first = verifier.update(&data).unwrap_err();
        assert_eq!(first.offset, 10);
        // Even correct continuation keeps reporting the original fault.
        let again = verifier.update(&[0u8; 4]).unwrap_err();
        assert_eq!(again, first);
        assert_eq!(verifier.verified(), 0);
    }

    #[test]
    fn verify_prefix_matches_generator() {
        let data = PayloadGen::stream_prefix(1234, 10_000);
        verify_prefix(1234, &data).unwrap();
        verify_prefix(1234, &data[.. 1]).unwrap();
        verify_prefix(1234, &[]).unwrap();
        assert!(verify_prefix(4321, &data).is_err());
    }
}
