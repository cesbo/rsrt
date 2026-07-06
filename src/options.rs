//! Connection options.

use std::{
    fmt,
    time::Duration,
};

use zeroize::Zeroizing;

use crate::{
    crypto::{
        CryptoConfig,
        KeyLength,
        PASSPHRASE_MAX,
        PASSPHRASE_MIN,
    },
    error::SrtError,
};

/// Sender pacing mode: libsrt's SRTO_MAXBW / SRTO_INPUTBW /
/// SRTO_MININPUTBW / SRTO_OHEADBW collapsed into one sentinel-free enum.
/// All rates are bytes per second and denote the wire budget: the pacing
/// formula charges payload + 44 bytes of UDP/IPv4+SRT header per packet
/// (docs/spec/transmission.md §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Bandwidth {
    /// No pacing (the default). libsrt equivalent: SRTO_MAXBW = -1, which
    /// paces at BW_INFINITE (125_000_000 B/s, ~10.9 µs period) — below any
    /// achievable timer resolution, i.e. effectively unpaced. This
    /// implementation disables the pacer outright (spec-marked divergence).
    #[default]
    Unlimited,
    /// Absolute ceiling. libsrt: SRTO_MAXBW = bytes_per_sec (> 0).
    Max { bytes_per_sec: u64 },
    /// Ceiling relative to a declared constant input rate:
    /// `bytes_per_sec * (100 + overhead_pct) / 100` (integer division),
    /// fixed at connect. libsrt: SRTO_MAXBW = 0, SRTO_INPUTBW =
    /// bytes_per_sec, SRTO_OHEADBW = overhead_pct (5..=100).
    Input { bytes_per_sec: u64, overhead_pct: u8 },
    /// Ceiling relative to the measured input rate (sampled where the
    /// application submits payloads), floored by `min_bytes_per_sec`:
    /// `max(min_bytes_per_sec, measured) * (100 + overhead_pct) / 100`.
    /// Until the first ~500 ms sample window closes, effectively unpaced
    /// (libsrt fast-start: initial estimate = BW_INFINITE).
    /// libsrt: SRTO_MAXBW = 0, SRTO_INPUTBW = 0,
    /// SRTO_MININPUTBW = min_bytes_per_sec, SRTO_OHEADBW = overhead_pct.
    Estimated { min_bytes_per_sec: u64, overhead_pct: u8 },
}

impl Bandwidth {
    /// libsrt's SRTO_OHEADBW default (25 %).
    pub const DEFAULT_OVERHEAD_PCT: u8 = 25;

    /// Mirrors libsrt's setter ranges (SRT_EINVPARAM,
    /// socketconfig.cpp:225-322): explicit rates are nonzero (a libsrt 0
    /// selects a different mode, which the enum expresses structurally),
    /// `overhead_pct` within 5..=100 (0-4 are not settable in libsrt
    /// either), `min_bytes_per_sec` unrestricted.
    pub(crate) fn validate(&self) -> Result<(), SrtError> {
        match *self {
            Bandwidth::Max { bytes_per_sec: 0 } => {
                Err(SrtError::InvalidBandwidth("max bandwidth must be nonzero"))
            }
            Bandwidth::Input { bytes_per_sec: 0, .. } => Err(SrtError::InvalidBandwidth(
                "explicit input rate must be nonzero (use Bandwidth::Estimated for auto)",
            )),
            Bandwidth::Input { overhead_pct, .. } | Bandwidth::Estimated { overhead_pct, .. }
                if !(5 ..= 100).contains(&overhead_pct) =>
            {
                Err(SrtError::InvalidBandwidth("overhead_pct must be within 5..=100"))
            }
            _ => Ok(()),
        }
    }
}

/// Options for callers (`SrtSocket::connect`) and listeners
/// (`SrtListener::bind`). Defaults follow libsrt 1.4.4 live mode.
///
/// `Debug` is hand-written to redact the passphrase (like
/// `CryptoConfig`'s): options structs get logged, secrets must not.
#[derive(Clone)]
pub struct SrtOptions {
    /// Receiver-side TSBPD latency we request for the data we *receive*
    /// (SRTO_RCVLATENCY). Effective latency is the max of this and the
    /// peer's proposed sender latency. Default 120 ms.
    pub latency: Duration,
    /// Latency we propose for the data we *send* (SRTO_PEERLATENCY).
    /// Default 0 (peer's receiver latency wins).
    pub peer_latency: Duration,
    /// StreamID sent by a caller (SRTO_STREAMID), max 512 bytes.
    pub streamid: Option<String>,
    /// MTU including IP/UDP headers (SRTO_MSS). Default 1500.
    pub mss: u32,
    /// Maximum flow window (packets in flight). Default 8192.
    pub flow_window: u32,
    /// Receive buffer capacity, packets. Default 8192.
    pub recv_buffer_pkts: usize,
    /// Send buffer capacity, packets. Default 8192.
    pub send_buffer_pkts: usize,
    /// Caller handshake overall timeout. Default 3 s.
    pub connect_timeout: Duration,
    /// Connection is broken after this long without any packet from the
    /// peer. Default 5 s.
    pub peer_idle_timeout: Duration,
    /// Connection is broken with `CloseReason::DataIdle` after this long
    /// without a data packet from the peer - keepalives and other control
    /// traffic do not count, unlike `peer_idle_timeout`, which any packet
    /// resets. The window starts at connection establishment and resets on
    /// every data arrival, decryptable or not - a stream of undecryptable
    /// data keeps the connection alive. `None` (the default) disables the
    /// check. A library extension; the SRT spec has no equivalent timer.
    pub data_idle_timeout: Option<Duration>,
    /// Sender pacing ceiling (SRTO_MAXBW / SRTO_INPUTBW / SRTO_MININPUTBW /
    /// SRTO_OHEADBW). Default `Bandwidth::Unlimited` = libsrt's default
    /// (MAXBW = -1): effectively unpaced. Harmless/inert on receive-only
    /// sockets. Fixed at connect time (this crate has no runtime option
    /// mutation; libsrt allows live changes — spec-marked divergence).
    pub bandwidth: Bandwidth,
    /// UDP socket receive buffer size in bytes (SO_RCVBUF), if set.
    pub udp_recv_buffer: Option<usize>,
    /// Encryption passphrase (SRTO_PASSPHRASE). `None` or empty =
    /// unencrypted. When set: 10..=80 bytes (libsrt's code accepts 80
    /// despite `srt.h` documenting 79; docs/spec/encryption.md §2).
    /// Encryption is always enforced (libsrt's default
    /// SRTO_ENFORCEDENCRYPTION=true): a peer whose encryption setup does
    /// not match ours (both-or-neither passphrase, and it must be the
    /// right one) is rejected during the handshake.
    /// Zeroize-on-drop, like every other copy of the root secret
    /// (`CryptoConfig::passphrase`, the derived keys): options structs
    /// are cloned per connection and must not strand the passphrase in
    /// freed heap. Plain `String`s convert with `.into()`.
    pub passphrase: Option<Zeroizing<String>>,
    /// SEK/KEK length (SRTO_PBKEYLEN). `None` = libsrt default: a caller
    /// with a passphrase uses AES-128; a listener adopts the caller's KMREQ
    /// length regardless (docs/spec/encryption.md §7).
    pub pbkeylen: Option<KeyLength>,
    /// Packets per SEK before key refresh (SRTO_KMREFRESHRATE).
    /// `None` or `Some(0)` = 2^24 (docs/spec/encryption.md §10.1). Must be
    /// < 2^31: the CTR IV counts packets by the 31-bit sequence number, so
    /// one SEK kept across a seqno wrap would reuse keystream (§9.2).
    pub km_refresh_rate: Option<u32>,
    /// Refresh pre-announce window (SRTO_KMPREANNOUNCE): the new key is
    /// announced this many packets before the switch, the old one retired
    /// this many after. Must satisfy `pa <= (rr - 1) / 2`. `None` or
    /// `Some(0)` = `(rr - 1) / 2` when `km_refresh_rate` is explicitly
    /// set, else 2^16 (docs/spec/encryption.md §2, §10.1).
    pub km_preannounce: Option<u32>,
}

impl fmt::Debug for SrtOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtOptions")
            .field("latency", &self.latency)
            .field("peer_latency", &self.peer_latency)
            .field("streamid", &self.streamid)
            .field("mss", &self.mss)
            .field("flow_window", &self.flow_window)
            .field("recv_buffer_pkts", &self.recv_buffer_pkts)
            .field("send_buffer_pkts", &self.send_buffer_pkts)
            .field("connect_timeout", &self.connect_timeout)
            .field("peer_idle_timeout", &self.peer_idle_timeout)
            .field("data_idle_timeout", &self.data_idle_timeout)
            .field("bandwidth", &self.bandwidth)
            .field("udp_recv_buffer", &self.udp_recv_buffer)
            .field("passphrase", &self.passphrase.as_ref().map(|_| "<redacted>"))
            .field("pbkeylen", &self.pbkeylen)
            .field("km_refresh_rate", &self.km_refresh_rate)
            .field("km_preannounce", &self.km_preannounce)
            .finish()
    }
}

impl Default for SrtOptions {
    fn default() -> Self {
        SrtOptions {
            latency: Duration::from_millis(120),
            peer_latency: Duration::ZERO,
            streamid: None,
            mss: 1500,
            flow_window: 8192,
            recv_buffer_pkts: 8192,
            send_buffer_pkts: 8192,
            connect_timeout: Duration::from_secs(3),
            peer_idle_timeout: Duration::from_secs(5),
            data_idle_timeout: None,
            bandwidth: Bandwidth::Unlimited,
            udp_recv_buffer: None,
            passphrase: None,
            pbkeylen: None,
            km_refresh_rate: None,
            km_preannounce: None,
        }
    }
}

impl SrtOptions {
    /// Maximum live-mode payload per packet: MSS − 28 (IPv4+UDP) − 16 (SRT).
    pub fn max_payload(&self) -> usize {
        (self.mss as usize).saturating_sub(44)
    }

    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    pub fn peer_latency(mut self, latency: Duration) -> Self {
        self.peer_latency = latency;
        self
    }

    pub fn streamid(mut self, streamid: impl Into<String>) -> Self {
        self.streamid = Some(streamid.into());
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn peer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.peer_idle_timeout = timeout;
        self
    }

    pub fn data_idle_timeout(mut self, timeout: Duration) -> Self {
        self.data_idle_timeout = Some(timeout);
        self
    }

    pub fn bandwidth(mut self, bandwidth: Bandwidth) -> Self {
        self.bandwidth = bandwidth;
        self
    }

    pub fn passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.passphrase = Some(Zeroizing::new(passphrase.into()));
        self
    }

    pub fn pbkeylen(mut self, len: KeyLength) -> Self {
        self.pbkeylen = Some(len);
        self
    }

    /// Resolves the encryption options (docs/spec/encryption.md §2):
    /// `Ok(None)` = unencrypted. Mirrors libsrt validation: passphrase
    /// 10..=80 bytes, `km_refresh_rate < 2^31` (unrepresentable through
    /// libsrt's `int` option API, and §9.2 forbids it — keystream reuse),
    /// `km_preannounce <= (km_refresh_rate - 1) / 2`.
    pub(crate) fn crypto_config(&self) -> Result<Option<CryptoConfig>, SrtError> {
        let Some(pw) = self.passphrase.as_deref().filter(|p| !p.is_empty()) else {
            return Ok(None);
        };
        if pw.len() < PASSPHRASE_MIN || pw.len() > PASSPHRASE_MAX {
            return Err(SrtError::InvalidPassphrase);
        }
        let rr_explicit = !matches!(self.km_refresh_rate, None | Some(0));
        let rr = match self.km_refresh_rate {
            None | Some(0) => 0x0100_0000, // 2^24 (§10.1)
            // The CTR IV's pki is the 31-bit wire seqno (§9.2): one SEK
            // kept active across a seqno wrap encrypts two packets under
            // the same counter block (two-time pad). libsrt's `int`
            // option range ends at 2^31 - 1; §9.2: "never configure
            // SRTO_KMREFRESHRATE >= 2^31".
            Some(rr) if rr >= 0x8000_0000 => {
                return Err(SrtError::InvalidKmParameters(
                    "km_refresh_rate must be < 2^31 (CTR keystream reuse)",
                ));
            }
            Some(rr) => rr,
        };
        let max_pa = rr.saturating_sub(1) / 2;
        let pa = match self.km_preannounce {
            // §2: libsrt's SRTO_KMREFRESHRATE setter force-sets an unset
            // pre-announce to the maximum (rr - 1) / 2; srtcore's 2^16
            // default only applies when the rate is default too (§10.1).
            None | Some(0) if rr_explicit => max_pa,
            None | Some(0) => 0x1_0000, // 2^16 (§10.1)
            Some(pa) if pa > max_pa => {
                return Err(SrtError::InvalidKmParameters(
                    "km_preannounce must be <= (km_refresh_rate - 1) / 2",
                ));
            }
            Some(pa) => pa,
        };
        Ok(Some(CryptoConfig {
            passphrase: pw.as_bytes().to_vec(),
            key_len: self.pbkeylen.unwrap_or(KeyLength::Aes128),
            km_refresh_rate: rr,
            km_preannounce: pa,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_passphrase() {
        // The manual `Debug` exists solely for this guarantee: options
        // structs end up in logs, the passphrase must not.
        let secret = "correct horse battery staple";
        let opts = SrtOptions::default().passphrase(secret);
        let dbg = format!("{opts:?}");
        assert!(!dbg.contains(secret), "passphrase leaked: {dbg}");
        assert!(dbg.contains("<redacted>"), "marker missing: {dbg}");
        // Unset stays visibly unset (None, not a redaction marker).
        let dbg = format!("{:?}", SrtOptions::default());
        assert!(dbg.contains("passphrase: None"), "{dbg}");
    }

    #[test]
    fn km_defaults_resolve_per_spec() {
        // All-default: RR = 2^24, PA = srtcore's 2^16 (§10.1); Some(0)
        // means "default" on both options, like libsrt's 0.
        let zeroes = {
            let mut opts = SrtOptions::default().passphrase("0123456789");
            opts.km_refresh_rate = Some(0);
            opts.km_preannounce = Some(0);
            opts
        };
        for opts in [SrtOptions::default().passphrase("0123456789"), zeroes] {
            let cfg = opts.crypto_config().unwrap().unwrap();
            assert_eq!(cfg.km_refresh_rate, 0x0100_0000);
            assert_eq!(cfg.km_preannounce, 0x1_0000);
        }
    }

    #[test]
    fn explicit_refresh_rate_force_sets_default_preannounce() {
        // §2: libsrt's SRTO_KMREFRESHRATE setter resolves an unset
        // pre-announce to (RR - 1) / 2, NOT min(2^16, (RR - 1) / 2)
        // (socketconfig.cpp) — the refresh KMREQ wire timing and the
        // dual-key overlap window must match an identically configured
        // libsrt 1.4.4 sender.
        let mut opts = SrtOptions::default().passphrase("0123456789");
        opts.km_refresh_rate = Some(0x10_0000); // 2^20
        let cfg = opts.crypto_config().unwrap().unwrap();
        assert_eq!(cfg.km_refresh_rate, 0x10_0000);
        assert_eq!(cfg.km_preannounce, (0x10_0000 - 1) / 2); // 524287, not 65536
        // An explicit pre-announce still wins over the force-set.
        opts.km_preannounce = Some(1000);
        let cfg = opts.crypto_config().unwrap().unwrap();
        assert_eq!(cfg.km_preannounce, 1000);
    }

    #[test]
    fn default_bandwidth_is_unlimited() {
        // Hard design constraint: default behavior stays exactly as before
        // pacing existed — `Unlimited` must construct no pacer at all
        // (docs/spec/transmission.md §3.3, spec-marked divergence from
        // libsrt's BW_INFINITE-paced MAXBW = -1 default).
        assert_eq!(SrtOptions::default().bandwidth, Bandwidth::Unlimited);
        assert_eq!(Bandwidth::default(), Bandwidth::Unlimited);
        // libsrt's SRTO_OHEADBW default (socketconfig.h).
        assert_eq!(Bandwidth::DEFAULT_OVERHEAD_PCT, 25);
    }

    #[test]
    fn bandwidth_validate_rejects_zero_rates() {
        // libsrt setter semantics: MAXBW = 0 and INPUTBW = 0 select
        // *different modes* (auto estimation) rather than a zero ceiling;
        // the enum expresses those modes structurally, so an explicit
        // zero rate can only be a configuration mistake.
        assert!(Bandwidth::Unlimited.validate().is_ok());
        assert!(Bandwidth::Max { bytes_per_sec: 1 }.validate().is_ok());
        let err = Bandwidth::Max { bytes_per_sec: 0 }.validate().unwrap_err();
        assert!(matches!(err, SrtError::InvalidBandwidth(_)), "{err:?}");
        let err = Bandwidth::Input { bytes_per_sec: 0, overhead_pct: 25 }
            .validate()
            .unwrap_err();
        assert!(matches!(err, SrtError::InvalidBandwidth(_)), "{err:?}");
        // A zero *minimum* is fine: it means "trust the estimator alone"
        // (libsrt SRTO_MININPUTBW default 0).
        assert!(Bandwidth::Estimated { min_bytes_per_sec: 0, overhead_pct: 25 }
            .validate()
            .is_ok());
    }

    #[test]
    fn bandwidth_validate_overhead_pct_range() {
        // SRTO_OHEADBW accepts exactly 5..=100 (SRT_EINVPARAM outside,
        // socketconfig.cpp:312-322) — 0-4 are not settable in libsrt
        // either, so the docs' "avoid 0" advice is moot.
        for pct in [5, 25, 100] {
            assert!(Bandwidth::Input { bytes_per_sec: 1, overhead_pct: pct }
                .validate()
                .is_ok());
            assert!(Bandwidth::Estimated { min_bytes_per_sec: 1, overhead_pct: pct }
                .validate()
                .is_ok());
        }
        for pct in [0, 4, 101, u8::MAX] {
            let err = Bandwidth::Input { bytes_per_sec: 1, overhead_pct: pct }
                .validate()
                .unwrap_err();
            assert!(matches!(err, SrtError::InvalidBandwidth(_)), "{err:?}");
            let err = Bandwidth::Estimated { min_bytes_per_sec: 1, overhead_pct: pct }
                .validate()
                .unwrap_err();
            assert!(matches!(err, SrtError::InvalidBandwidth(_)), "{err:?}");
        }
    }

    #[test]
    fn km_refresh_rate_rejects_seqno_wrap_range() {
        // §9.2: the CTR IV's pki is the 31-bit seqno, so RR >= 2^31
        // keeps one SEK active across a wrap → keystream reuse (two-time
        // pad). libsrt's `int` option API cannot even express such
        // values; reject them instead of silently accepting.
        let mut opts = SrtOptions::default().passphrase("0123456789");
        for rr in [0x8000_0000u32, u32::MAX] {
            opts.km_refresh_rate = Some(rr);
            let err = opts.crypto_config().unwrap_err();
            assert!(matches!(err, SrtError::InvalidKmParameters(_)), "{err:?}");
        }
        // Boundary: 2^31 - 1 (libsrt's own maximum) still resolves, with
        // the §2 force-set pre-announce.
        opts.km_refresh_rate = Some(0x7FFF_FFFF);
        let cfg = opts.crypto_config().unwrap().unwrap();
        assert_eq!(cfg.km_refresh_rate, 0x7FFF_FFFF);
        assert_eq!(cfg.km_preannounce, 0x3FFF_FFFF);
    }
}
