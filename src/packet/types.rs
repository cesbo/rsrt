//! Protocol integer types with wrap-aware arithmetic.
//!
//! All wrap-aware sequence/message-number math in the crate lives here —
//! never do modular arithmetic on raw `u32` values elsewhere.

use std::fmt;

/// 31-bit packet sequence number, arithmetic mod 2^31.
///
/// See docs/spec/packets.md.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SeqNumber(u32);

impl SeqNumber {
    pub const MASK: u32 = 0x7FFF_FFFF;

    /// Wraps the value into the 31-bit range.
    pub const fn new(value: u32) -> Self {
        SeqNumber(value & Self::MASK)
    }

    pub const fn value(self) -> u32 {
        self.0
    }

    pub fn next(self) -> Self {
        self.add(1)
    }

    pub fn prev(self) -> Self {
        self.add(-1)
    }

    /// `self + n` mod 2^31 (`n` may be negative).
    ///
    /// Deliberately an inherent method, not `std::ops::Add`: the wrapping
    /// mod-2^31 semantics should stay visible at call sites.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, n: i32) -> Self {
        SeqNumber(self.0.wrapping_add(n as u32) & Self::MASK)
    }

    /// Shortest signed distance `self - other` in mod-2^31 space.
    ///
    /// Positive when `self` is ahead of `other`. The result is in
    /// `-2^30 ..= 2^30 - 1`; comparisons between sequence numbers more than
    /// 2^30 apart are meaningless (cannot happen with sane flow windows).
    pub fn diff(self, other: SeqNumber) -> i32 {
        let d = self.0.wrapping_sub(other.0) & Self::MASK;
        if d > Self::MASK / 2 {
            (d as i64 - (1i64 << 31)) as i32
        } else {
            d as i32
        }
    }
}

impl fmt::Debug for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

impl fmt::Display for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// 26-bit message number, arithmetic mod 2^26.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MsgNumber(u32);

impl MsgNumber {
    pub const MASK: u32 = 0x03FF_FFFF;

    pub const fn new(value: u32) -> Self {
        MsgNumber(value & Self::MASK)
    }

    pub const fn value(self) -> u32 {
        self.0
    }

    pub fn next(self) -> Self {
        MsgNumber(self.0.wrapping_add(1) & Self::MASK)
    }
}

impl fmt::Debug for MsgNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "msg#{}", self.0)
    }
}

/// SRT socket identifier. `0` is reserved for handshake-phase packets.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SocketId(pub u32);

impl SocketId {
    pub const HANDSHAKE: SocketId = SocketId(0);
}

impl fmt::Debug for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sid:{:#010x}", self.0)
    }
}

/// 32-bit wire timestamp: microseconds since the sending socket was created.
/// Wraps around every ~71.6 minutes; see `core::time::TimestampExtender`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Timestamp(pub u32);

impl Timestamp {
    pub const fn as_micros(self) -> u32 {
        self.0
    }

    /// Wire-order difference `self - other`, wrapping (mod 2^32).
    pub fn wrapping_sub(self, other: Timestamp) -> u32 {
        self.0.wrapping_sub(other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_wraps_forward() {
        let max = SeqNumber::new(SeqNumber::MASK);
        assert_eq!(max.next(), SeqNumber::new(0));
        assert_eq!(SeqNumber::new(0).prev(), max);
    }

    #[test]
    fn seq_diff_across_wrap() {
        let max = SeqNumber::new(SeqNumber::MASK);
        let zero = SeqNumber::new(0);
        assert_eq!(zero.diff(max), 1);
        assert_eq!(max.diff(zero), -1);
        assert_eq!(zero.diff(zero), 0);
        assert_eq!(SeqNumber::new(1000).diff(SeqNumber::new(10)), 990);
        assert_eq!(SeqNumber::new(10).diff(SeqNumber::new(1000)), -990);
    }

    #[test]
    fn seq_add_negative() {
        assert_eq!(
            SeqNumber::new(5).add(-10),
            SeqNumber::new(SeqNumber::MASK - 4)
        );
    }

    #[test]
    fn msg_wraps() {
        let max = MsgNumber::new(MsgNumber::MASK);
        assert_eq!(max.next(), MsgNumber::new(0));
    }

    #[test]
    fn timestamp_wrapping_sub() {
        let a = Timestamp(10);
        let b = Timestamp(u32::MAX - 9);
        assert_eq!(a.wrapping_sub(b), 20);
    }
}
