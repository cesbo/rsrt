//! Seeded deterministic PRNG for reproducible tests.
//!
//! SplitMix64 (Steele/Lea/Flood via Vigna's reference implementation): tiny,
//! statistically solid for test purposes, and dependency-free. The same seed
//! always yields the same stream on every platform — loss patterns, payloads
//! and proxy decisions in the integration tests are therefore reproducible.

/// SplitMix64 pseudo-random generator.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform value in `[0, 1)` (53-bit precision).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Bernoulli trial: `true` with probability `p` (clamped to `[0, 1]`).
    ///
    /// Always consumes exactly one `next_u64` draw, even for `p <= 0` or
    /// `p >= 1`, so decision streams stay aligned when only probabilities
    /// differ between two runs.
    pub fn chance(&mut self, p: f64) -> bool {
        self.next_f64() < p
    }

    /// Uniform value in `[0, bound)`; `bound` must be non-zero.
    ///
    /// Plain modulo — the tiny bias is irrelevant for tests.
    pub fn next_below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    /// Fills `buf` with random bytes: successive `next_u64` words serialized
    /// little-endian. Byte `i` of the stream depends only on the seed and `i`,
    /// never on how the stream is chunked into `fill` calls of whole words —
    /// [`crate::support::payload`] relies on this layout.
    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut chunks = buf.chunks_exact_mut(8);
        for chunk in &mut chunks {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            let word = self.next_u64().to_le_bytes();
            tail.copy_from_slice(&word[.. tail.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vector for seed 0 (Vigna's splitmix64.c output).
    #[test]
    fn reference_vector_seed_zero() {
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
        assert_eq!(rng.next_u64(), 0xF88B_B8A8_724C_81EC);
    }

    #[test]
    fn reference_vector_nonzero_seed() {
        let mut rng = SplitMix64::new(0x1234_5678_9ABC_DEF0);
        assert_eq!(rng.next_u64(), 0x1619_22C6_45CE_50E8);
        assert_eq!(rng.next_u64(), 0xAD76_0CAF_A169_7B60);
    }

    #[test]
    fn same_seed_same_stream() {
        let mut a = SplitMix64::new(7);
        let mut b = SplitMix64::new(7);
        for _ in 0 .. 1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn fill_matches_word_stream_le() {
        // 12 bytes = one full word + a 4-byte tail from the next word.
        let mut rng = SplitMix64::new(42);
        let mut buf = [0u8; 12];
        rng.fill(&mut buf);

        let mut words = SplitMix64::new(42);
        let mut expected = Vec::new();
        expected.extend_from_slice(&words.next_u64().to_le_bytes());
        expected.extend_from_slice(&words.next_u64().to_le_bytes());
        assert_eq!(&buf[..], &expected[.. 12]);
    }

    #[test]
    fn next_f64_in_unit_range() {
        let mut rng = SplitMix64::new(1);
        for _ in 0 .. 10_000 {
            let v = rng.next_f64();
            assert!((0.0 .. 1.0).contains(&v), "out of range: {v}");
        }
    }

    #[test]
    fn chance_extremes_and_rough_fairness() {
        let mut rng = SplitMix64::new(2);
        for _ in 0 .. 1000 {
            assert!(!rng.chance(0.0));
            assert!(rng.chance(1.0));
        }
        let mut hits = 0;
        for _ in 0 .. 10_000 {
            if rng.chance(0.5) {
                hits += 1;
            }
        }
        // 10k Bernoulli(0.5) trials: allow a generous ±5σ-ish band.
        assert!((4500 .. 5500).contains(&hits), "hits = {hits}");
    }
}
