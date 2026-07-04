//! Per-connection encryption engine — docs/spec/encryption.md §1, §6,
//! §10, §11.
//!
//! One `Crypto` per connection. After HSv5 KMX a single SEK pair is shared
//! by BOTH transmission directions (§1): the initiator (caller) generates
//! the key material; the responder unwraps it and uses the same SEKs for
//! its own sending. Each side later refreshes the key for the direction it
//! sends on (§10) via in-stream `UMSG_EXT` KMREQ/KMRSP (§11).
//!
//! Policy stays OUTSIDE this type: the §8 enforcement matrix (reject vs
//! continue-unsecured, silence vs status KMRSP) is applied by
//! `core::handshake` / `core::Connection` using the outcomes returned here.

use std::{
    fmt,
    time::{
        Duration,
        Instant,
    },
};

use tracing::{
    debug,
    trace,
    warn,
};
use zeroize::Zeroize;

use crate::packet::{
    EncryptionFlags,
    SeqNumber,
};

use super::{
    ctr::CtrCipher,
    keys::{
        derive_kek,
        random_salt,
        unwrap_key,
        wrap_key,
        Kek,
        KeyLength,
        SecretKey,
    },
    km::{
        KmKeys,
        KmMessage,
        KmResponse,
        KmState,
    },
    CryptoError,
};

/// In-stream KMREQ retransmission budget (`crypto.cpp:SRT_MAX_KMRETRY`;
/// §11.2): one immediate send plus up to this many paced resends.
const KM_MAX_RETRY: u32 = 10;

/// SEK slot indices: `ctx_pair[0]` is even, `[1]` odd
/// (`hcrypt.c:sHaiCrypt_PrepareHandle`; §9.1).
const EVEN: usize = 0;
const ODD: usize = 1;

/// Fixed KM header length, for the srtcore §6.2 step-1 pre-checks (same
/// value as `km.rs`'s private `KM_HEADER_LEN`).
const KM_HEADER_LEN: usize = 16;

/// Resolved crypto parameters (see `SrtOptions::crypto_config`).
#[derive(Clone)]
pub struct CryptoConfig {
    /// Raw passphrase bytes, already validated to 10..=80 (§2).
    pub passphrase: Vec<u8>,
    /// SEK/KEK length. Initiator default Aes128; a responder adopts the
    /// KMREQ's length regardless of its own setting (§7 trap).
    pub key_len: KeyLength,
    /// Packets per SEK before refresh; resolved default 2^24 (§10.1).
    pub km_refresh_rate: u32,
    /// Pre-announce window; resolved default `(rr − 1) / 2` when the
    /// refresh rate was explicitly set, else 2^16 (§2, §10.1).
    pub km_preannounce: u32,
}

impl fmt::Debug for CryptoConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoConfig")
            .field("passphrase", &"<redacted>")
            .field("key_len", &self.key_len)
            .field("km_refresh_rate", &self.km_refresh_rate)
            .field("km_preannounce", &self.km_preannounce)
            .finish()
    }
}

/// The passphrase is the connection's ROOT secret — every session KEK
/// (past and future) is PBKDF2-derivable from it plus the wire-public
/// salt (§4.2) — so every config copy scrubs it on drop, like the keys
/// it derives ([`SecretKey`]; libsrt: `crypto.cpp:CCryptoControl::close`
/// memsets `m_KmSecret`). Scrubbed-on-drop heap can't be observed from
/// safe code, so the regression guard is structural: `Drop` makes
/// functional record update on `CryptoConfig` an E0509 error, which the
/// doctest below pins — remove the impl and this compiles, failing the
/// doctest.
///
/// ```compile_fail,E0509
/// use srt::crypto::{CryptoConfig, KeyLength};
///
/// let base = CryptoConfig {
///     passphrase: b"correct horse battery".to_vec(),
///     key_len: KeyLength::Aes128,
///     km_refresh_rate: 1 << 24,
///     km_preannounce: 1 << 16,
/// };
/// let _ = CryptoConfig { km_refresh_rate: 16, ..base };
/// ```
impl Drop for CryptoConfig {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

/// Outcome of processing a KMREQ (handshake extension or in-stream).
#[derive(Debug)]
pub enum KmReqOutcome {
    /// Keys installed; send back this byte-identical echo KMRSP (§6.2).
    Installed(Vec<u8>),
    /// Validation/unwrap failed. Policy (§8; encryption is always
    /// enforced): in the handshake ⇒ reject (BadSecret/NoSecret → reject
    /// code); in-stream ⇒ total silence (§11.3).
    Failed(KmState),
}

/// Outcome of a KMRSP on the side that sent the KMREQ (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmRspOutcome {
    /// Echo matched the outstanding KMREQ; retries stop, snd state SECURED.
    Confirmed,
    /// Peer reported failure (1-word status KMRSP).
    Failed(KmState),
    /// Echo didn't match the outstanding KMREQ or was malformed; ignored
    /// (retries continue) — libsrt logs and drops these.
    Ignored,
}

/// TX SEK slot role in the §10.1 refresh cycle. Mirrors the HaiCrypt ctx
/// statuses that matter on the SRT path: ACTIVE, KEYED+ANNOUNCE and
/// DEPRECATED (`hcrypt_ctx.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxKeyState {
    /// Encrypting outgoing packets now.
    Active,
    /// Pre-announced refresh key waiting for the §10.1 switch.
    Announced,
    /// Old key inside the post-switch decommission window.
    Deprecated,
}

/// One TX SEK with its refresh bookkeeping (§10).
struct TxKey {
    /// Raw key bytes, kept because a refresh re-wraps BOTH keys into the
    /// dual-SEK KM (§4.3) — the cipher alone cannot reproduce them.
    key: SecretKey,
    /// AES key schedule for `key`, expanded once at install and reused
    /// per packet (like libsrt's per-key `CRYSPR_AESCTX`).
    cipher: CtrCipher,
    /// Packets encrypted under this key: 1 at connection setup, 0 for a
    /// refreshed key; the §10.1 thresholds are strict `>` on this counter
    /// (§15 trap).
    pkt_cnt: u32,
    state: TxKeyState,
}

/// Cached KMREQ send slot (§10.3, §11.2). The §6.3 confirmation is a byte
/// `memcmp` against exactly `blob`.
struct OutstandingKmReq {
    /// Encoded KM message, byte-exact as (to be) sent.
    blob: Vec<u8>,
    /// Remaining in-stream retransmissions. 0 = stop retrying — the key is
    /// used at the §10.1 thresholds regardless (§11.2); a responder adopts
    /// the caller's KM with 0 retries (§6.2 trap).
    retries: u32,
    /// Last in-stream (re)send; `None` until first paced by
    /// [`Crypto::on_ack`] (handshake attachment does not pace here).
    last_send: Option<Instant>,
}

/// Per-connection HaiCrypt engine: encrypt/decrypt, KMX bookkeeping and
/// the TX key-refresh state machine.
pub struct Crypto {
    cfg: CryptoConfig,
    /// Connection salt (§4.1): generated once by the initiator or adopted
    /// from the handshake KMREQ by the responder; refresh reuses it, so
    /// the CTR nonce and the KEK stay stable.
    salt: [u8; 16],
    /// KEK = PBKDF2(passphrase, salt[8..]) (§4.2), derived once.
    kek: Kek,
    /// TX SEK slots `[even, odd]`; the §10 machine rotates them.
    tx: [Option<TxKey>; 2],
    /// Active TX slot index ([`EVEN`]/[`ODD`]); selects the KK bits (§9.1).
    active: usize,
    /// RX SEK slots `[even, odd]`, as ready-to-use key schedules (the
    /// raw RX bytes are never needed after install). Mid-stream KMREQs
    /// install here ONLY (§11.3), and a key dies only by being
    /// overwritten (§10.4).
    rx: [Option<CtrCipher>; 2],
    /// Salt for RX IVs — always == `salt` with stock libsrt peers (§4.1);
    /// tracked separately in case a peer's KM ever changes it. (libsrt
    /// keeps it per RX context; a single copy suffices because dual KMs
    /// update both slots and stock peers never change it.)
    rx_salt: [u8; 16],
    /// RX KEK, present only after a peer KM changed the salt/KLen (§4.2:
    /// "RX re-derives the KEK only when the salt bytes or KLen change").
    rx_kek: Option<Kek>,
    /// Sender-side `SRT_KM_S_*` (§1.1).
    snd_state: KmState,
    /// Receiver-side `SRT_KM_S_*` (§1.1).
    rcv_state: KmState,
    /// KMREQ send slot: initial KM for a caller, the caller's KM (0
    /// retries) for a responder, or the latest refresh KM (§10.3).
    outstanding: Option<OutstandingKmReq>,
    /// Completed §10.1 "Switch" transitions (TX SEK rotations); surfaced
    /// through `core::Stats::km_refreshes`.
    key_switches: u64,
}

impl Crypto {
    /// Initiator (HSv5 caller): generates the salt and the first (even)
    /// SEK, derives the KEK and caches the wrapped KMREQ blob for the
    /// CONCLUSION extension (§6.1). Never fails.
    ///
    /// §1.1: SND is SECURING while the KM exchange is pending; RCV stays
    /// UNSECURED until the peer's echo KMRSP confirms (§6.3).
    pub fn new_initiator(cfg: CryptoConfig) -> Crypto {
        // §4.1/§4.2: one salt and one KEK per connection; refresh reuses
        // both.
        let salt = random_salt();
        let kek = derive_kek(&cfg.passphrase, &salt, cfg.key_len);
        // §9.1 trap: the first SEK of a connection is always the EVEN key.
        let sek = SecretKey::generate(cfg.key_len);
        let cipher = CtrCipher::new(&sek);
        let wrapped = wrap_key(&kek, sek.as_slice());
        let blob = KmMessage {
            keys: KmKeys::Even,
            key_len: cfg.key_len,
            salt,
            wrapped,
        }
        .encode();
        debug!(
            key_len = cfg.key_len.bytes(),
            kmreq_len = blob.len(),
            "key material generated"
        );
        Crypto {
            // §1: the initiator's TX context is cloned into RX — one SEK
            // serves both directions until the first refresh.
            rx: [Some(cipher.clone()), None],
            tx: [
                Some(TxKey {
                    key: sek,
                    cipher,
                    pkt_cnt: 1, // §10: the initial key's counter starts at 1
                    state: TxKeyState::Active,
                }),
                None,
            ],
            active: EVEN,
            salt,
            rx_salt: salt,
            rx_kek: None,
            kek,
            snd_state: KmState::Securing,
            rcv_state: KmState::Unsecured,
            outstanding: Some(OutstandingKmReq {
                blob,
                retries: KM_MAX_RETRY,
                last_send: None,
            }),
            key_switches: 0,
            cfg,
        }
    }

    /// Responder (listener), from the caller's handshake KMREQ: derives
    /// the KEK (adopting the KMREQ's key length, §7), unwraps and installs
    /// the SEK(s) for both directions, and returns the echo-KMRSP payload
    /// (§6.2). `Err` carries the failure KM state for the §8 policy
    /// (BadSecret for unwrap failure, NoSecret is decided by the caller
    /// when there is no local passphrase — this constructor requires one).
    pub fn new_responder(mut cfg: CryptoConfig, kmreq: &[u8]) -> Result<(Crypto, Vec<u8>), KmState> {
        // srtcore pre-checks (§6.2 step 1): these two failures are
        // answered BADSECRET by srtcore itself; every later validation
        // failure is NOSECRET class except the unwrap ICV (§3.1).
        if kmreq.len() <= KM_HEADER_LEN || kmreq[15] == 0 {
            warn!(kmreq_len = kmreq.len(), "handshake KMREQ failed pre-checks");
            return Err(KmState::BadSecret);
        }
        let msg = KmMessage::parse(kmreq).map_err(|err| {
            warn!(?err, "handshake KMREQ rejected");
            KmState::NoSecret
        })?;
        // §6.2 step 2 / §7 trap: adopt the sender's key length for BOTH
        // directions, whatever the local PBKEYLEN says — never an error.
        cfg.key_len = msg.key_len;
        let kek = derive_kek(&cfg.passphrase, &msg.salt, msg.key_len);
        // §4.3: the unwrap ICV is the protocol's only wrong-passphrase
        // detector.
        let sek = unwrap_key(&kek, &msg.wrapped).map_err(|err| match err {
            CryptoError::WrongSecret => KmState::BadSecret,
            // Unreachable: parse pinned the exact wrap length (§3.1).
            _ => KmState::NoSecret,
        })?;
        // §1/§6.2 step 5 (bidirectional): install the caller's SEK(s) for
        // RX and clone them into TX. The initial KM is even-only on the
        // wire; odd/dual are handled for robustness.
        let seks = split_seks(&msg, sek);
        let active = if seks[EVEN].is_some() { EVEN } else { ODD };
        let mut tx: [Option<TxKey>; 2] = [None, None];
        let mut rx: [Option<CtrCipher>; 2] = [None, None];
        for (slot, key) in seks.into_iter().enumerate() {
            let Some(key) = key else { continue };
            let cipher = CtrCipher::new(&key);
            rx[slot] = Some(cipher.clone());
            tx[slot] = Some(TxKey {
                key,
                cipher,
                pkt_cnt: if slot == active { 1 } else { 0 },
                state: if slot == active {
                    TxKeyState::Active
                } else {
                    TxKeyState::Announced
                },
            });
        }
        debug!(key_len = cfg.key_len.bytes(), keys = ?msg.keys, "responder installed caller SEK");
        let crypto = Crypto {
            salt: msg.salt,
            rx_salt: msg.salt,
            rx_kek: None,
            kek,
            tx,
            rx,
            active,
            // §1: the responder inherited the caller's keys — both
            // directions are SECURED immediately.
            snd_state: KmState::Secured,
            rcv_state: KmState::Secured,
            // §6.2 trap: the caller's KM becomes the responder's own snd
            // KM slot with 0 retries ("Don't start sending them upon
            // connection").
            outstanding: Some(OutstandingKmReq {
                blob: kmreq.to_vec(),
                retries: 0,
                last_send: None,
            }),
            key_switches: 0,
            cfg,
        };
        // §6.2 step 4: the echo KMRSP is the received message
        // byte-for-byte — never re-encoded (§6.3 memcmp trap).
        Ok((crypto, kmreq.to_vec()))
    }

    /// KMREQ payload currently outstanding (initial for a caller until
    /// confirmed, or a refresh KMREQ), for handshake attachment/retries.
    /// On a responder this is the adopted caller KM — its send slot 0
    /// (§6.2), never re-sent in-stream because its retries are 0.
    pub fn kmreq(&self) -> Option<Vec<u8>> {
        self.outstanding.as_ref().map(|out| out.blob.clone())
    }

    /// Encrypts in place with the active SEK; returns the KK bits for the
    /// data header and ticks the refresh packet counter (§10.1). Called
    /// once per packet when it is stored in the send buffer — the buffer
    /// keeps ciphertext, so retransmissions resend identical bytes with
    /// identical KK bits (§9.3). Never fails.
    pub fn encrypt(&mut self, seq: SeqNumber, payload: &mut [u8]) -> EncryptionFlags {
        // §9.4: HaiCrypt reports a zero-length encrypt as failure and live
        // mode never produces one — core must not send empty payloads.
        debug_assert!(!payload.is_empty(), "never encrypt a zero-length payload");
        let slot = self.tx[self.active]
            .as_mut()
            .expect("active TX SEK installed at construction");
        // §9.2: `seq` is the 32-bit header word 0 (MSB 0 for data).
        slot.cipher.apply_keystream(&self.salt, seq.value(), payload);
        slot.pkt_cnt = slot.pkt_cnt.wrapping_add(1);
        if self.active == EVEN {
            EncryptionFlags::Even
        } else {
            EncryptionFlags::Odd
        }
    }

    /// Decrypts in place. `EncryptionFlags::None` on an encrypted link is
    /// cleartext passthrough (§9.4 trap: no enforcement). `Both` (illegal
    /// on data) selects the odd slot like libsrt (§9.4 trap). `Err(NoKey)`
    /// ⇒ undecryptable: the packet must still occupy its sequence slot
    /// (ACKed, never NAK-repaired) but must not be delivered.
    pub fn decrypt(
        &mut self,
        seq: SeqNumber,
        kk: EncryptionFlags,
        payload: &mut [u8],
    ) -> Result<(), CryptoError> {
        // §9.4: routing is purely mechanical — `ctx_pair[KK >> 1]`, so
        // KK=1 → even, KK=2 → odd and the illegal-on-data KK=3 → odd.
        let slot = match kk {
            EncryptionFlags::None => return Ok(()),
            EncryptionFlags::Even => EVEN,
            EncryptionFlags::Odd | EncryptionFlags::Both => ODD,
        };
        // §9.4 state gate (`crypto.cpp:CCryptoControl::decrypt`): any rcv
        // state other than SECURED drops encrypted packets WITHOUT
        // attempting decryption. After a failed KMX (§8 row 11) the RX
        // slots may still hold OUR OWN SEK while the peer encrypts with
        // its fake one — CTR has no integrity check, so decrypting here
        // would deliver pseudorandom garbage as valid payload.
        if self.rcv_state == KmState::Unsecured {
            // Surprise encryption before KMX secured RX: a `Crypto`
            // always has a passphrase, so UNSECURED flips to SECURING
            // (never NOSECRET) and the packet is dropped (§1.1).
            self.rcv_state = KmState::Securing;
            warn!("peer sent encrypted data while KMX is pending; dropped");
            return Err(CryptoError::NoKey);
        }
        if self.rcv_state != KmState::Secured {
            return Err(CryptoError::NoKey);
        }
        let Some(cipher) = self.rx[slot].as_ref() else {
            // Referenced slot not keyed: undecryptable (§9.4) — core ACKs
            // the packet, counts it and never delivers it.
            return Err(CryptoError::NoKey);
        };
        // AES-CTR cannot fail and has no integrity check (§9.4): a
        // wrong-but-installed key "succeeds" and delivers garbage.
        cipher.apply_keystream(&self.rx_salt, seq.value(), payload);
        Ok(())
    }

    /// ACK-driven housekeeping (§10.2, §11.2), called on every ACK the
    /// sender half receives: evaluates the refresh thresholds
    /// (pre-announce → switch → decommission, §10.1) and the KMREQ
    /// retransmission pacing (1.5 × SRTT, max 10 retries). Returns a KMREQ
    /// payload to send now, if one is due.
    pub fn on_ack(&mut self, now: Instant, srtt_us: u32) -> Option<Vec<u8>> {
        // §11.2: skip entirely when snd is UNSECURED (peer has no crypto,
        // after a §6.3 UNSECURED report) — `sendKeysToPeer`'s only gate.
        if self.snd_state == KmState::Unsecured {
            return None;
        }
        // §10.1 machine first: a pre-announce KM supersedes the
        // outstanding one (libsrt keys refresh KMs into the same send
        // slot, §10.3) and is sent immediately with a fresh retry budget.
        if let Some(blob) = self.tick_refresh() {
            self.outstanding = Some(OutstandingKmReq {
                blob: blob.clone(),
                retries: KM_MAX_RETRY,
                last_send: Some(now),
            });
            return Some(blob);
        }
        // §11.2 pacing: resend the outstanding KMREQ every 1.5 × SRTT
        // until an echo or error KMRSP arrives or retries run out — the
        // §10.1 thresholds switch keys regardless.
        let out = self.outstanding.as_mut()?;
        if out.retries == 0 {
            return None;
        }
        let pace = Duration::from_micros(u64::from(srtt_us) * 3 / 2);
        if out.last_send.is_some_and(|last| now < last + pace) {
            return None;
        }
        out.retries -= 1;
        out.last_send = Some(now);
        trace!(retries_left = out.retries, "KMREQ retransmitted");
        Some(out.blob.clone())
    }

    /// In-stream KMREQ (`UMSG_EXT`, §11.3): install refreshed key(s) and
    /// produce the echo KMRSP, or fail with a KM state for the §8 policy.
    pub fn handle_kmreq(&mut self, payload: &[u8]) -> KmReqOutcome {
        // srtcore pre-checks (§6.2 step 1): BADSECRET class, rcv only.
        if payload.len() <= KM_HEADER_LEN || payload[15] == 0 {
            warn!(kmreq_len = payload.len(), "in-stream KMREQ failed pre-checks");
            self.rcv_state = KmState::BadSecret;
            return KmReqOutcome::Failed(KmState::BadSecret);
        }
        let msg = match KmMessage::parse(payload) {
            Ok(msg) => msg,
            Err(err) => {
                // §6.2 step 4, −1 class: structural/unsupported ⇒ both
                // states NOSECRET.
                warn!(?err, "in-stream KMREQ rejected");
                self.snd_state = KmState::NoSecret;
                self.rcv_state = KmState::NoSecret;
                return KmReqOutcome::Failed(KmState::NoSecret);
            }
        };
        match self.install_rx(&msg) {
            Ok(()) => {
                // §11.3: a successful refresh (re)secures RX
                // unconditionally; TX is untouched — a mid-stream KM is
                // never cloned into the send direction (§11.3 trap).
                self.rcv_state = KmState::Secured;
                debug!(keys = ?msg.keys, "in-stream KM installed");
                KmReqOutcome::Installed(payload.to_vec())
            }
            Err(CryptoError::WrongSecret) => {
                // §6.2 step 4, −2: wrong passphrase.
                self.snd_state = KmState::BadSecret;
                self.rcv_state = KmState::BadSecret;
                KmReqOutcome::Failed(KmState::BadSecret)
            }
            Err(err) => {
                warn!(?err, "in-stream KMREQ key install failed");
                self.snd_state = KmState::NoSecret;
                self.rcv_state = KmState::NoSecret;
                KmReqOutcome::Failed(KmState::NoSecret)
            }
        }
    }

    /// KMRSP from the handshake extension or `UMSG_EXT` (§6.3).
    pub fn handle_kmrsp(&mut self, payload: &[u8]) -> KmRspOutcome {
        match KmResponse::parse(payload) {
            Ok(KmResponse::Status(state)) => self.peer_km_failure(Some(state)),
            // A 4-byte word with an unknown value is §6.3's "anything
            // else" row, not a malformed response.
            Err(_) if payload.len() == 4 => self.peer_km_failure(None),
            Ok(KmResponse::Echo(echo)) => match self.outstanding.as_ref() {
                // §6.3: byte-exact echo of the outstanding KMREQ — the
                // slot's retries stop, both directions SECURED.
                Some(out) if out.blob == echo => {
                    self.outstanding = None;
                    self.snd_state = KmState::Secured;
                    self.rcv_state = KmState::Secured;
                    debug!("KMREQ confirmed by echo KMRSP");
                    KmRspOutcome::Confirmed
                }
                _ => {
                    // Mismatched echo: log and drop; retries continue.
                    //
                    // ADJUDICATED divergence (kept): libsrt sets
                    // Snd=Rcv=BADSECRET here (§6.3;
                    // `crypto.cpp:processSrtMsg_KMRSP`) WITHOUT zeroing
                    // retries — via its decrypt state gate that blackholes
                    // its own RX (despite intact keys) until a matching
                    // echo or peer KMREQ re-secures it. Neither behavior
                    // emits anything, the handshake caller aborts
                    // UNSECURE either way (`core::handshake` catch-all),
                    // and a stock 1.4.4 peer only produces a full-length
                    // mismatch via a stale echo of a superseded refresh
                    // KMREQ (its echo is a byte-exact copy) — so
                    // Ignored-and-keep-retrying converges to SECURED with
                    // no wire-visible difference and no self-inflicted
                    // delivery outage.
                    warn!(kmrsp_len = echo.len(), "KMRSP echo does not match outstanding KMREQ");
                    KmRspOutcome::Ignored
                }
            },
            Err(_) => {
                warn!(kmrsp_len = payload.len(), "malformed KMRSP ignored");
                KmRspOutcome::Ignored
            }
        }
    }

    /// Sender-side KM state (`SRT_KM_S_*`): SECURED once the peer confirmed
    /// our KMREQ (or, on a responder, immediately — it inherited the
    /// caller's keys).
    #[cfg(test)]
    pub fn snd_km_state(&self) -> KmState {
        self.snd_state
    }

    /// Receiver-side KM state.
    #[cfg(test)]
    pub fn rcv_km_state(&self) -> KmState {
        self.rcv_state
    }

    /// Completed TX key switches (§10.1 "Switch" transitions): how many
    /// times the send direction rotated to a refreshed SEK. Feeds
    /// `core::Stats::km_refreshes`.
    pub fn key_switches(&self) -> u64 {
        self.key_switches
    }

    /// One §10.1 evaluation: at most one transition per tick, checked
    /// pre-announce → switch → decommission. libsrt checks switch first
    /// and can flip-flop on `pkt_cnt == 0` or switch to a never-keyed
    /// context under pathological ACK gaps; the §10.1 quirks say not to
    /// copy that, so the switch here requires a pre-announced key and
    /// treats `pkt_cnt == 0` purely as the unsigned-rollover guard (§15).
    /// Returns the encoded dual-SEK KM when pre-announce fires.
    fn tick_refresh(&mut self) -> Option<Vec<u8>> {
        let rr = self.cfg.km_refresh_rate;
        let pa = self.cfg.km_preannounce;
        let cnt = self.tx[self.active]
            .as_ref()
            .expect("active TX SEK installed")
            .pkt_cnt;
        let alt = self.active ^ 1;
        let alt_state = self.tx[alt].as_ref().map(|key| key.state);

        // Pre-announce: fresh SEK for the other slot; the dual-SEK KM
        // wraps even‖odd, even FIRST regardless of which key is the new
        // one (§4.3 trap). Salt and KEK are reused (§4.1), so the peer
        // re-runs neither PBKDF2 nor changes its IV nonce.
        if cnt > rr.saturating_sub(pa) && alt_state != Some(TxKeyState::Announced) {
            let key = SecretKey::generate(self.cfg.key_len);
            self.tx[alt] = Some(TxKey {
                cipher: CtrCipher::new(&key),
                key,
                pkt_cnt: 0, // §10: a refreshed key's counter starts at 0
                state: TxKeyState::Announced,
            });
            let mut plain = Vec::with_capacity(2 * self.cfg.key_len.bytes());
            for slot in &self.tx {
                let key = slot.as_ref().expect("both slots keyed at pre-announce");
                plain.extend_from_slice(key.key.as_slice());
            }
            let wrapped = wrap_key(&self.kek, &plain);
            plain.zeroize();
            debug!(pkt_cnt = cnt, "key refresh pre-announced");
            return Some(
                KmMessage {
                    keys: KmKeys::Both,
                    key_len: self.cfg.key_len,
                    salt: self.salt,
                    wrapped,
                }
                .encode(),
            );
        }
        // Switch: flip the KK bits to the pre-announced key. The sender
        // switches when the counter says so, confirmed or not (§11.2).
        if (cnt > rr || cnt == 0) && alt_state == Some(TxKeyState::Announced) {
            self.tx[self.active]
                .as_mut()
                .expect("active TX SEK installed")
                .state = TxKeyState::Deprecated;
            self.tx[alt].as_mut().expect("state checked above").state = TxKeyState::Active;
            self.active = alt;
            self.key_switches += 1;
            debug!(pkt_cnt = cnt, to_even = alt == EVEN, "SEK switched");
            return None;
        }
        // Decommission: `cnt` now counts the NEW key's packets; the old
        // key dies PA packets after the switch. TX bookkeeping only — RX
        // keys are never proactively expired (§10.4).
        if alt_state == Some(TxKeyState::Deprecated) && cnt > pa {
            self.tx[alt] = None;
            debug!(pkt_cnt = cnt, "old SEK decommissioned");
        }
        None
    }

    /// Unwraps a parsed KM message and installs its SEK(s) into the RX
    /// slots (§4.3 positional mapping, §10.4 dual install). The KEK is
    /// re-derived only if the salt or key length changed (§4.2) — never
    /// with stock libsrt peers, whose refreshes reuse both.
    fn install_rx(&mut self, msg: &KmMessage) -> Result<(), CryptoError> {
        let current = self.rx_kek.as_ref().unwrap_or(&self.kek);
        let fresh = if msg.salt != self.rx_salt || msg.key_len.bytes() != current.as_slice().len()
        {
            Some(derive_kek(&self.cfg.passphrase, &msg.salt, msg.key_len))
        } else {
            None
        };
        let sek = unwrap_key(fresh.as_ref().unwrap_or(current), &msg.wrapped)?;
        for (slot, key) in self.rx.iter_mut().zip(split_seks(msg, sek)) {
            if let Some(key) = key {
                // The raw bytes are dropped (and zeroized) right here —
                // only the expanded schedule is kept for the RX side.
                *slot = Some(CtrCipher::new(&key));
            }
        }
        // Committed only on success: a rejected KM must not disturb the
        // salt/KEK still decrypting in-flight packets.
        if fresh.is_some() {
            self.rx_kek = fresh;
        }
        self.rx_salt = msg.salt;
        Ok(())
    }

    /// §6.3 1-word status KMRSP: zero the retry counters, apply the state
    /// table. `None` = unknown status word ("anything else" row). Note
    /// `UNSECURED` is not an error even with encryption enforced (libsrt
    /// returns 0 there): core connects anyway.
    fn peer_km_failure(&mut self, reported: Option<KmState>) -> KmRspOutcome {
        // "Both slots' retries zeroed first" — the cached KM itself stays
        // (it is still re-attached to repeated handshakes).
        if let Some(out) = self.outstanding.as_mut() {
            out.retries = 0;
        }
        let (snd, rcv, outcome) = match reported {
            Some(KmState::BadSecret) => {
                (KmState::BadSecret, KmState::BadSecret, KmState::BadSecret)
            }
            // Peer has no passphrase: it cannot read us, but its own data
            // arrives unencrypted.
            Some(KmState::NoSecret) => (KmState::NoSecret, KmState::Unsecured, KmState::NoSecret),
            // Peer has no crypto at all.
            Some(KmState::Unsecured) => {
                (KmState::Unsecured, KmState::NoSecret, KmState::Unsecured)
            }
            // "anything else": SECURING/SECURED or an unknown word.
            _ => (KmState::NoSecret, KmState::NoSecret, KmState::NoSecret),
        };
        self.snd_state = snd;
        self.rcv_state = rcv;
        warn!(state = ?reported, "peer reported KM failure");
        KmRspOutcome::Failed(outcome)
    }
}

impl fmt::Debug for Crypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately terse: never expose key material.
        write!(f, "Crypto(..)")
    }
}

/// Splits an unwrapped KM payload into `[even, odd]` SEKs. Dual blobs are
/// even‖odd — even FIRST positionally, always (§4.3 trap); each half is
/// `key_len` bytes.
fn split_seks(msg: &KmMessage, sek: SecretKey) -> [Option<SecretKey>; 2] {
    match msg.keys {
        KmKeys::Even => [Some(sek), None],
        KmKeys::Odd => [None, Some(sek)],
        KmKeys::Both => {
            let (even, odd) = sek.as_slice().split_at(msg.key_len.bytes());
            // `sek` (the concatenated pair) is zeroized when dropped here.
            [
                Some(SecretKey::from_bytes(even)),
                Some(SecretKey::from_bytes(odd)),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &[u8] = b"correct horse battery";

    fn config(key_len: KeyLength) -> CryptoConfig {
        CryptoConfig {
            passphrase: PASSPHRASE.to_vec(),
            key_len,
            km_refresh_rate: 0x0100_0000, // resolved defaults (§10.1)
            km_preannounce: 0x1_0000,
        }
    }

    /// Tiny thresholds for refresh tests. With `rr = 16, pa = 4` and the
    /// initial counter starting at 1 (§10): pre-announce after packet 12
    /// (cnt 13 > 12), switch after packet 16 (cnt 17 > 16), decommission
    /// 5 new-key packets later (cnt 5 > 4).
    fn refresh_config() -> CryptoConfig {
        // No functional record update: `CryptoConfig` is `Drop` (E0509).
        let mut cfg = config(KeyLength::Aes128);
        cfg.km_refresh_rate = 16;
        cfg.km_preannounce = 4;
        cfg
    }

    fn seq(n: u32) -> SeqNumber {
        SeqNumber::new(n)
    }

    /// Completed initiator↔responder KMX (§6): initial KMREQ from the
    /// caller, echo KMRSP back, confirmed.
    fn kmx_pair_with(icfg: CryptoConfig, rcfg: CryptoConfig) -> (Crypto, Crypto) {
        let mut initiator = Crypto::new_initiator(icfg);
        let kmreq = initiator.kmreq().expect("initial KMREQ cached");
        let (responder, kmrsp) = Crypto::new_responder(rcfg, &kmreq).expect("KMX must succeed");
        assert_eq!(initiator.handle_kmrsp(&kmrsp), KmRspOutcome::Confirmed);
        (initiator, responder)
    }

    fn kmx_pair(key_len: KeyLength) -> (Crypto, Crypto) {
        kmx_pair_with(config(key_len), config(key_len))
    }

    /// Encrypts on `tx`, decrypts on `rx`, asserting the payload survives
    /// the trip; returns the KK flags the packet carried.
    fn roundtrip(tx: &mut Crypto, rx: &mut Crypto, n: u32) -> EncryptionFlags {
        let clear: Vec<u8> = (0 .. 100).map(|i| (i as u8).wrapping_mul(31) ^ n as u8).collect();
        let mut buf = clear.clone();
        let flags = tx.encrypt(seq(n), &mut buf);
        assert_ne!(buf, clear, "payload must be transformed");
        rx.decrypt(seq(n), flags, &mut buf).expect("decrypt must succeed");
        assert_eq!(buf, clear, "payload must survive the roundtrip");
        flags
    }

    // -- Handshake KMX through the public API (§1, §6) ------------------------

    #[test]
    fn kmx_secures_both_directions_all_key_lengths() {
        for key_len in [KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256] {
            let (mut caller, mut listener) = kmx_pair(key_len);
            assert_eq!(caller.snd_km_state(), KmState::Secured, "{key_len:?}");
            assert_eq!(caller.rcv_km_state(), KmState::Secured, "{key_len:?}");
            assert_eq!(listener.snd_km_state(), KmState::Secured, "{key_len:?}");
            assert_eq!(listener.rcv_km_state(), KmState::Secured, "{key_len:?}");
            // Confirmed: the caller's KMREQ is no longer outstanding.
            assert!(caller.kmreq().is_none(), "{key_len:?}");

            // §9.1 trap: the first key of a connection is EVEN — and §1:
            // the one SEK serves both directions.
            assert_eq!(
                roundtrip(&mut caller, &mut listener, 42),
                EncryptionFlags::Even,
                "{key_len:?}"
            );
            assert_eq!(
                roundtrip(&mut listener, &mut caller, 43),
                EncryptionFlags::Even,
                "{key_len:?}"
            );
        }
    }

    #[test]
    fn initiator_states_before_confirmation() {
        // §1.1: SECURING with a passphrase; RCV UNSECURED until the echo.
        let initiator = Crypto::new_initiator(config(KeyLength::Aes128));
        assert_eq!(initiator.snd_km_state(), KmState::Securing);
        assert_eq!(initiator.rcv_km_state(), KmState::Unsecured);
    }

    #[test]
    fn initial_kmreq_is_even_single_key() {
        let initiator = Crypto::new_initiator(config(KeyLength::Aes128));
        let blob = initiator.kmreq().unwrap();
        assert_eq!(blob.len(), 56); // §3: single-key KLen 16
        let msg = KmMessage::parse(&blob).unwrap();
        assert_eq!(msg.keys, KmKeys::Even);
        assert_eq!(msg.key_len, KeyLength::Aes128);
    }

    #[test]
    fn responder_echo_is_byte_identical() {
        // §6.2/§6.3 trap: the success KMRSP is the received KMREQ echoed
        // byte-for-byte, never re-encoded.
        let initiator = Crypto::new_initiator(config(KeyLength::Aes192));
        let kmreq = initiator.kmreq().unwrap();
        let (_, kmrsp) = Crypto::new_responder(config(KeyLength::Aes192), &kmreq).unwrap();
        assert_eq!(kmrsp, kmreq);
    }

    #[test]
    fn responder_adopts_kmreq_key_length() {
        // §7 trap: the KMREQ's KLen silently overrides the local PBKEYLEN
        // — never a rejection, and the adopted length feeds the
        // responder's own refreshes.
        let icfg = config(KeyLength::Aes256);
        let rcfg = refresh_config(); // Aes128 + tiny thresholds
        let (mut caller, mut listener) = kmx_pair_with(icfg, rcfg);
        assert_eq!(listener.cfg.key_len, KeyLength::Aes256);
        roundtrip(&mut listener, &mut caller, 7);

        // Drive the listener's own refresh: its dual KM must carry the
        // adopted 32-byte keys.
        let t0 = Instant::now();
        let mut km = None;
        for n in 0 .. 16 {
            let mut buf = [0u8; 32];
            listener.encrypt(seq(n), &mut buf);
            if let Some(blob) = listener.on_ack(t0, 100_000) {
                km = Some(blob);
                break;
            }
        }
        let msg = KmMessage::parse(&km.expect("refresh KM emitted")).unwrap();
        assert_eq!(msg.keys, KmKeys::Both);
        assert_eq!(msg.key_len, KeyLength::Aes256);
    }

    #[test]
    fn wrong_passphrase_is_bad_secret() {
        // §4.3: the unwrap ICV is the only wrong-passphrase detector.
        let initiator = Crypto::new_initiator(config(KeyLength::Aes128));
        let kmreq = initiator.kmreq().unwrap();
        let mut cfg = config(KeyLength::Aes128);
        cfg.passphrase = b"wrong passphrase".to_vec();
        assert_eq!(
            Crypto::new_responder(cfg, &kmreq).unwrap_err(),
            KmState::BadSecret
        );
    }

    #[test]
    fn responder_failure_state_mapping() {
        let initiator = Crypto::new_initiator(config(KeyLength::Aes128));
        let kmreq = initiator.kmreq().unwrap();

        // srtcore pre-checks (§6.2 step 1) ⇒ BADSECRET.
        let err = Crypto::new_responder(config(KeyLength::Aes128), &kmreq[.. 16]).unwrap_err();
        assert_eq!(err, KmState::BadSecret);
        let mut zero_klen = kmreq.clone();
        zero_klen[15] = 0;
        let err = Crypto::new_responder(config(KeyLength::Aes128), &zero_klen).unwrap_err();
        assert_eq!(err, KmState::BadSecret);

        // Carrier/structural failures (−1 class, §3.1) ⇒ NOSECRET.
        let mut bad_sign = kmreq.clone();
        bad_sign[1] = 0xAA;
        let err = Crypto::new_responder(config(KeyLength::Aes128), &bad_sign).unwrap_err();
        assert_eq!(err, KmState::NoSecret);
        let mut bad_cipher = kmreq.clone();
        bad_cipher[8] = 1;
        let err = Crypto::new_responder(config(KeyLength::Aes128), &bad_cipher).unwrap_err();
        assert_eq!(err, KmState::NoSecret);

        // Corrupted wrap (ICV failure) ⇒ BADSECRET.
        let mut bad_wrap = kmreq;
        *bad_wrap.last_mut().unwrap() ^= 0x01;
        let err = Crypto::new_responder(config(KeyLength::Aes128), &bad_wrap).unwrap_err();
        assert_eq!(err, KmState::BadSecret);
    }

    // -- Data path (§9) --------------------------------------------------------

    #[test]
    fn decrypt_none_is_cleartext_passthrough() {
        // §9.4 trap: KK=0 bypasses decryption even on a secured link.
        let (_, mut listener) = kmx_pair(KeyLength::Aes128);
        let clear = b"plaintext stays".to_vec();
        let mut buf = clear.clone();
        listener
            .decrypt(seq(9), EncryptionFlags::None, &mut buf)
            .unwrap();
        assert_eq!(buf, clear);
    }

    #[test]
    fn decrypt_missing_slot_is_no_key() {
        // Only the even key exists after the initial KMX; §9.4: KK=2 and
        // the illegal KK=3 both route to the (empty) odd slot.
        let (_, mut listener) = kmx_pair(KeyLength::Aes128);
        let mut buf = [0xA5u8; 16];
        assert_eq!(
            listener.decrypt(seq(9), EncryptionFlags::Odd, &mut buf),
            Err(CryptoError::NoKey)
        );
        assert_eq!(
            listener.decrypt(seq(9), EncryptionFlags::Both, &mut buf),
            Err(CryptoError::NoKey)
        );
        // The payload must be untouched by a failed decrypt.
        assert_eq!(buf, [0xA5u8; 16]);
    }

    #[test]
    fn decrypt_gated_until_rcv_secured() {
        // §9.4 (`crypto.cpp:CCryptoControl::decrypt`): after a BADSECRET
        // KMRSP (e.g. an in-stream status word) the endpoint keeps its
        // OWN SEK in rx[EVEN] while the peer encrypts with a key we never
        // installed — any rcv state != SECURED must drop without
        // attempting decryption, or CTR "succeeds" and delivers
        // pseudorandom garbage as valid payload.
        let mut caller = Crypto::new_initiator(config(KeyLength::Aes128));
        assert_eq!(
            caller.handle_kmrsp(&[4, 0, 0, 0]), // 1-word BADSECRET status
            KmRspOutcome::Failed(KmState::BadSecret)
        );
        assert!(caller.rx[EVEN].is_some(), "own SEK still installed");
        let mut buf = [0x5Au8; 24];
        assert_eq!(
            caller.decrypt(seq(1), EncryptionFlags::Even, &mut buf),
            Err(CryptoError::NoKey)
        );
        assert_eq!(buf, [0x5Au8; 24], "payload untouched by the drop");
    }

    #[test]
    fn decrypt_unsecured_flips_to_securing_and_recovers() {
        // §1.1/§9.4 surprise encryption: encrypted data reaching an
        // initiator before the echo KMRSP confirmed — UNSECURED flips to
        // SECURING (a passphrase is always present) and nothing is
        // delivered until the KMX completes; KK=0 cleartext still passes.
        let mut caller = Crypto::new_initiator(config(KeyLength::Aes128));
        let kmreq = caller.kmreq().unwrap();
        let (mut listener, kmrsp) =
            Crypto::new_responder(config(KeyLength::Aes128), &kmreq).unwrap();

        // The responder (SECURED immediately) sends before the caller
        // processed the echo.
        let clear = b"too early".to_vec();
        let mut buf = clear.clone();
        let flags = listener.encrypt(seq(5), &mut buf);
        let ct = buf.clone();
        assert_eq!(caller.decrypt(seq(5), flags, &mut buf), Err(CryptoError::NoKey));
        assert_eq!(buf, ct, "payload untouched by the drop");
        assert_eq!(caller.rcv_km_state(), KmState::Securing);
        // Still dropped while SECURING (!= SECURED)...
        assert_eq!(caller.decrypt(seq(5), flags, &mut buf), Err(CryptoError::NoKey));
        // ...but KK=0 passes through the gate untouched (§9.4 trap).
        let mut plain = b"cleartext".to_vec();
        caller.decrypt(seq(6), EncryptionFlags::None, &mut plain).unwrap();
        assert_eq!(plain, b"cleartext");

        // The echo confirmation re-secures RX; the same packet decrypts.
        assert_eq!(caller.handle_kmrsp(&kmrsp), KmRspOutcome::Confirmed);
        caller.decrypt(seq(5), flags, &mut buf).unwrap();
        assert_eq!(buf, clear);
    }

    #[test]
    fn decrypt_both_selects_odd_slot() {
        // §9.4 trap: an illegal KK=3 data packet maps to the ODD context.
        let (mut caller, mut listener) = refreshed_pair();
        let clear = b"odd-slot payload".to_vec();
        let mut buf = clear.clone();
        assert_eq!(caller.encrypt(seq(900), &mut buf), EncryptionFlags::Odd);
        listener
            .decrypt(seq(900), EncryptionFlags::Both, &mut buf)
            .unwrap();
        assert_eq!(buf, clear);
    }

    // -- Refresh state machine (§10, §11) ---------------------------------------

    /// Drives `caller` through packets `range`, ticking `on_ack` after
    /// each; returns `(packet number, KM blob)` for every emitted KMREQ.
    fn drive(
        caller: &mut Crypto,
        listener: &mut Crypto,
        range: std::ops::RangeInclusive<u32>,
        now: Instant,
        expect_flags: impl Fn(u32) -> EncryptionFlags,
    ) -> Vec<(u32, Vec<u8>)> {
        let mut kms = Vec::new();
        for n in range {
            let flags = roundtrip(caller, listener, n);
            assert_eq!(flags, expect_flags(n), "packet {n}");
            if let Some(blob) = caller.on_ack(now, 100_000) {
                kms.push((n, blob));
            }
        }
        kms
    }

    /// A pair driven through one complete refresh cycle: the caller's
    /// active key is now the ODD slot and the listener holds both keys.
    fn refreshed_pair() -> (Crypto, Crypto) {
        let (mut caller, mut listener) = kmx_pair_with(refresh_config(), config(KeyLength::Aes128));
        let t0 = Instant::now();
        let kms = drive(&mut caller, &mut listener, 1 ..= 12, t0, |_| EncryptionFlags::Even);
        let (_, km) = kms.into_iter().next().expect("pre-announce KM");
        let KmReqOutcome::Installed(echo) = listener.handle_kmreq(&km) else {
            panic!("refresh KM must install");
        };
        assert_eq!(caller.handle_kmrsp(&echo), KmRspOutcome::Confirmed);
        // Packets 13..=16 still even; the switch fires on the ACK after
        // packet 16 (cnt 17 > 16), so 17.. are odd.
        drive(&mut caller, &mut listener, 13 ..= 16, t0, |_| EncryptionFlags::Even);
        drive(&mut caller, &mut listener, 17 ..= 17, t0, |_| EncryptionFlags::Odd);
        (caller, listener)
    }

    #[test]
    fn refresh_cycle_end_to_end() {
        let (mut caller, mut listener) =
            kmx_pair_with(refresh_config(), config(KeyLength::Aes128));
        let t0 = Instant::now();
        let clear = b"replayed dual-window packet".to_vec();

        // Packets 1..=11: below every threshold, no KM traffic.
        assert!(drive(&mut caller, &mut listener, 1 ..= 11, t0, |_| EncryptionFlags::Even)
            .is_empty());

        // Packet 12 crosses pre-announce (cnt 13 > 16 − 4): dual-SEK KM.
        // Sent by hand so its ciphertext can be replayed later (a §9.3
        // retransmission of an old-key packet).
        let mut even_ct = clear.clone();
        assert_eq!(caller.encrypt(seq(12), &mut even_ct), EncryptionFlags::Even);
        let km = caller.on_ack(t0, 100_000).expect("pre-announce at packet 12");
        let msg = KmMessage::parse(&km).unwrap();
        assert_eq!(msg.keys, KmKeys::Both);
        // §4.1 trap: refresh reuses the salt (same KEK, same IV nonce).
        assert_eq!(msg.salt, caller.salt);

        // Peer installs BOTH keys from the one message and echoes it.
        let KmReqOutcome::Installed(echo) = listener.handle_kmreq(&km) else {
            panic!("refresh KM must install");
        };
        assert_eq!(echo, km);
        assert_eq!(listener.rcv_km_state(), KmState::Secured);
        assert_eq!(caller.handle_kmrsp(&echo), KmRspOutcome::Confirmed);
        assert!(caller.kmreq().is_none());

        // Dual-key window: old-key (even) packets still decrypt...
        let mut buf = even_ct.clone();
        listener.decrypt(seq(12), EncryptionFlags::Even, &mut buf).unwrap();
        assert_eq!(buf, clear);

        // Packets 13..=16 stay on the even key (switch is strict cnt > RR,
        // evaluated on the ACK path only, §10.2): the flip shows at 17.
        drive(&mut caller, &mut listener, 13 ..= 16, t0, |_| EncryptionFlags::Even);
        drive(&mut caller, &mut listener, 17 ..= 20, t0, |_| EncryptionFlags::Odd);
        // ...and even-key retransmissions decrypt after the switch too.
        let mut buf = even_ct.clone();
        listener.decrypt(seq(12), EncryptionFlags::Even, &mut buf).unwrap();
        assert_eq!(buf, clear);

        // Counters reset: the odd key counts its own packets (4 so far).
        assert_eq!(caller.tx[ODD].as_ref().unwrap().pkt_cnt, 4);
        assert!(caller.tx[EVEN].is_some(), "old key inside the PA window");

        // Decommission: 5th new-key packet (cnt 5 > 4) retires the old
        // TX key — the listener's RX copy lives on (§10.4).
        drive(&mut caller, &mut listener, 21 ..= 21, t0, |_| EncryptionFlags::Odd);
        assert!(caller.tx[EVEN].is_none(), "old key decommissioned");
        assert!(listener.rx[EVEN].is_some(), "RX keys never expire");

        // Second cycle: pre-announce at odd cnt 13 (packet 29), switch
        // after packet 33 — the dual KM wraps the NEW even key first
        // (§4.3 trap), which the positional install must honor.
        let kms = drive(&mut caller, &mut listener, 22 ..= 29, t0, |_| EncryptionFlags::Odd);
        assert_eq!(kms.len(), 1);
        let (n, km2) = &kms[0];
        assert_eq!(*n, 29);
        let msg2 = KmMessage::parse(km2).unwrap();
        assert_eq!(msg2.keys, KmKeys::Both);
        assert_eq!(msg2.salt, caller.salt, "salt is stable across refreshes");
        let KmReqOutcome::Installed(echo2) = listener.handle_kmreq(km2) else {
            panic!("second refresh KM must install");
        };
        assert_eq!(caller.handle_kmrsp(&echo2), KmRspOutcome::Confirmed);
        drive(&mut caller, &mut listener, 30 ..= 32, t0, |_| EncryptionFlags::Odd);

        // Packet 33 (odd cnt 17 > 16) triggers the second switch; keep its
        // ciphertext for an after-the-switch replay.
        let mut odd_ct = clear.clone();
        assert_eq!(caller.encrypt(seq(33), &mut odd_ct), EncryptionFlags::Odd);
        assert!(caller.on_ack(t0, 100_000).is_none(), "switch emits nothing");

        // Back on the (new) even key: KK flips and decrypts fine.
        drive(&mut caller, &mut listener, 34 ..= 38, t0, |_| EncryptionFlags::Even);
        // Old odd-key packets keep decrypting throughout the window.
        let mut buf = odd_ct.clone();
        listener.decrypt(seq(33), EncryptionFlags::Odd, &mut buf).unwrap();
        assert_eq!(buf, clear);
    }

    #[test]
    fn switch_waits_for_preannounced_key() {
        // §10.1 quirk (b), not copied: with an ACK gap far past RR, the
        // first tick pre-announces (never switching to a non-keyed slot),
        // the second tick switches.
        let (mut caller, mut listener) =
            kmx_pair_with(refresh_config(), config(KeyLength::Aes128));
        let t0 = Instant::now();
        for n in 1 ..= 30 {
            // No ACKs at all while cnt runs far past RR = 16.
            assert_eq!(roundtrip(&mut caller, &mut listener, n), EncryptionFlags::Even);
        }
        let km = caller.on_ack(t0, 100_000).expect("first tick pre-announces");
        assert_eq!(KmMessage::parse(&km).unwrap().keys, KmKeys::Both);
        // Still even until the next tick — one transition per tick.
        assert_eq!(roundtrip(&mut caller, &mut listener, 31), EncryptionFlags::Even);
        let KmReqOutcome::Installed(_) = listener.handle_kmreq(&km) else {
            panic!("refresh KM must install");
        };
        assert!(caller.on_ack(t0, 100_000).is_none(), "second tick switches silently");
        assert_eq!(roundtrip(&mut caller, &mut listener, 32), EncryptionFlags::Odd);
    }

    #[test]
    fn midstream_kmreq_applies_to_rx_only() {
        // §11.3 trap: a peer's refresh KM must never touch our TX keys.
        let (mut caller, mut listener) = refreshed_pair();
        // `caller` now sends on its odd key; `listener` still sends on
        // the original (even) SEK, and the caller decrypts it fine even
        // though the caller's own even TX slot was rotated away.
        assert_eq!(caller.active, ODD);
        assert!(listener.tx[ODD].is_none(), "listener TX untouched by RX install");
        assert_eq!(listener.active, EVEN);
        assert_eq!(roundtrip(&mut listener, &mut caller, 500), EncryptionFlags::Even);
        assert_eq!(listener.snd_km_state(), KmState::Secured);
        assert_eq!(listener.rcv_km_state(), KmState::Secured);
    }

    #[test]
    fn duplicate_kmreq_is_reechoed() {
        // §10.4 trap: retried KMREQs are idempotent and always re-answered
        // with the full echo — the initiator's retries depend on it.
        let (mut caller, mut listener) =
            kmx_pair_with(refresh_config(), config(KeyLength::Aes128));
        let t0 = Instant::now();
        let (_, km) = drive(&mut caller, &mut listener, 1 ..= 12, t0, |_| EncryptionFlags::Even)
            .pop()
            .expect("pre-announce KM");
        for _ in 0 .. 2 {
            match listener.handle_kmreq(&km) {
                KmReqOutcome::Installed(echo) => assert_eq!(echo, km),
                KmReqOutcome::Failed(state) => panic!("duplicate rejected: {state:?}"),
            }
        }
        // Packets under both keys still decrypt after the double install.
        roundtrip(&mut caller, &mut listener, 600);
    }

    #[test]
    fn midstream_kmreq_failure_mapping() {
        let (mut caller, mut listener) =
            kmx_pair_with(refresh_config(), config(KeyLength::Aes128));
        let t0 = Instant::now();
        let (_, km) = drive(&mut caller, &mut listener, 1 ..= 12, t0, |_| EncryptionFlags::Even)
            .pop()
            .expect("pre-announce KM");

        // srtcore pre-checks ⇒ BADSECRET (rcv only, §6.2 step 1).
        let KmReqOutcome::Failed(state) = listener.handle_kmreq(&km[.. 10]) else {
            panic!("truncated KM must fail");
        };
        assert_eq!(state, KmState::BadSecret);
        assert_eq!(listener.rcv_km_state(), KmState::BadSecret);
        assert_eq!(listener.snd_km_state(), KmState::Secured);

        // Structural failure (−1 class) ⇒ both NOSECRET.
        let mut bad_se = km.clone();
        bad_se[10] = 1;
        let KmReqOutcome::Failed(state) = listener.handle_kmreq(&bad_se) else {
            panic!("bad SE must fail");
        };
        assert_eq!(state, KmState::NoSecret);
        assert_eq!(listener.rcv_km_state(), KmState::NoSecret);
        assert_eq!(listener.snd_km_state(), KmState::NoSecret);

        // Corrupted wrap ⇒ unwrap ICV failure ⇒ both BADSECRET. The
        // installed keys survive the rejected KM, but the §9.4 state gate
        // drops encrypted data while RX is not SECURED (crypto.cpp).
        let mut bad_wrap = km.clone();
        *bad_wrap.last_mut().unwrap() ^= 0x01;
        let KmReqOutcome::Failed(state) = listener.handle_kmreq(&bad_wrap) else {
            panic!("corrupt wrap must fail");
        };
        assert_eq!(state, KmState::BadSecret);
        let mut buf = [0x5Au8; 24];
        let flags = caller.encrypt(seq(700), &mut buf);
        assert_eq!(
            listener.decrypt(seq(700), flags, &mut buf),
            Err(CryptoError::NoKey),
            "no delivery while RX is BADSECRET"
        );

        // §11.3: a later good KMREQ re-secures RX unconditionally — and
        // the keys that survived the rejected KM decrypt again.
        let KmReqOutcome::Installed(_) = listener.handle_kmreq(&km) else {
            panic!("good KM must install");
        };
        assert_eq!(listener.rcv_km_state(), KmState::Secured);
        roundtrip(&mut caller, &mut listener, 701);
    }

    #[test]
    fn midstream_wrong_secret_is_bad_secret() {
        // Two unrelated engines: B cannot unwrap A's refresh KM.
        let (mut a, mut a_peer) = kmx_pair_with(refresh_config(), config(KeyLength::Aes128));
        let t0 = Instant::now();
        let (_, km) = drive(&mut a, &mut a_peer, 1 ..= 12, t0, |_| EncryptionFlags::Even)
            .pop()
            .expect("pre-announce KM");
        let mut cfg = config(KeyLength::Aes128);
        cfg.passphrase = b"a different secret".to_vec();
        let (_, mut b) = kmx_pair_with(cfg.clone(), cfg);
        let KmReqOutcome::Failed(state) = b.handle_kmreq(&km) else {
            panic!("foreign KM must fail");
        };
        assert_eq!(state, KmState::BadSecret);
        assert_eq!(b.rcv_km_state(), KmState::BadSecret);
        assert_eq!(b.snd_km_state(), KmState::BadSecret);
    }

    // -- KMREQ retries (§11.2) ---------------------------------------------------

    #[test]
    fn retry_pacing_and_exhaustion() {
        let (mut caller, mut listener) =
            kmx_pair_with(refresh_config(), config(KeyLength::Aes128));
        let t0 = Instant::now();
        let srtt = 100_000u32; // 100 ms ⇒ pace 150 ms
        let pace = Duration::from_millis(150);

        let (_, km) = drive(&mut caller, &mut listener, 1 ..= 12, t0, |_| EncryptionFlags::Even)
            .pop()
            .expect("pre-announce KM");
        assert_eq!(caller.kmreq().as_deref(), Some(&km[..]));

        // Not due before 1.5 × SRTT has elapsed since the initial send.
        assert!(caller.on_ack(t0, srtt).is_none());
        assert!(caller.on_ack(t0 + pace - Duration::from_millis(1), srtt).is_none());

        // Exactly 10 paced resends, byte-identical, then silence forever
        // (§11.2) — while the key material stays in place.
        let mut now = t0;
        for retry in 1 ..= KM_MAX_RETRY {
            now += pace;
            assert_eq!(caller.on_ack(now, srtt).as_deref(), Some(&km[..]), "retry {retry}");
        }
        now += pace;
        assert!(caller.on_ack(now, srtt).is_none(), "retries exhausted");
        assert!(caller.on_ack(now + pace * 100, srtt).is_none());

        // §11.2 trap: the sender still switches at RR with the KMREQ
        // unconfirmed; a receiver that truly lost it drops new-key data.
        for n in 13 ..= 16 {
            assert_eq!(roundtrip(&mut caller, &mut listener, n), EncryptionFlags::Even);
        }
        caller.on_ack(now, srtt); // switch tick
        let mut buf = [0x5Au8; 24];
        assert_eq!(caller.encrypt(seq(17), &mut buf), EncryptionFlags::Odd);
        assert_eq!(
            listener.decrypt(seq(17), EncryptionFlags::Odd, &mut buf),
            Err(CryptoError::NoKey),
            "peer without the refresh KM drops odd-key packets"
        );
    }

    #[test]
    fn unconfirmed_initial_kmreq_is_resent_on_ack() {
        // The initial KMREQ carries a full retry budget; if the handshake
        // KMRSP never confirmed it, the first ACK resends it in-stream —
        // this is also the §6.2 step 6 unsolicited fake-KM mechanism.
        let mut initiator = Crypto::new_initiator(config(KeyLength::Aes128));
        let kmreq = initiator.kmreq().unwrap();
        let t0 = Instant::now();
        assert_eq!(initiator.on_ack(t0, 100_000).as_deref(), Some(&kmreq[..]));
        // ...and paced afterwards.
        assert!(initiator.on_ack(t0, 100_000).is_none());
        assert_eq!(
            initiator
                .on_ack(t0 + Duration::from_millis(150), 100_000)
                .as_deref(),
            Some(&kmreq[..])
        );
    }

    #[test]
    fn responder_never_resends_adopted_kmreq() {
        // §6.2 trap: the caller's KM is recorded with 0 retries — the
        // responder must not start sending it upon connection.
        let (caller, mut listener) = kmx_pair(KeyLength::Aes128);
        let t0 = Instant::now();
        let _ = caller;
        assert!(listener.kmreq().is_some(), "slot 0 holds the adopted KM");
        for i in 0 .. 5 {
            let now = t0 + Duration::from_millis(200 * i);
            assert!(listener.on_ack(now, 100_000).is_none());
        }
    }

    // -- KMRSP processing (§6.3, §5.1) --------------------------------------------

    #[test]
    fn kmrsp_echo_mismatch_is_ignored() {
        let mut initiator = Crypto::new_initiator(config(KeyLength::Aes128));
        let mut corrupted = initiator.kmreq().unwrap();
        corrupted[20] ^= 0x01;
        assert_eq!(initiator.handle_kmrsp(&corrupted), KmRspOutcome::Ignored);
        // States and the outstanding KMREQ are untouched: retries go on.
        assert_eq!(initiator.snd_km_state(), KmState::Securing);
        assert_eq!(initiator.rcv_km_state(), KmState::Unsecured);
        assert!(initiator.kmreq().is_some());
        assert!(initiator.on_ack(Instant::now(), 100_000).is_some());
    }

    #[test]
    fn kmrsp_without_outstanding_is_ignored() {
        let (mut caller, _) = kmx_pair(KeyLength::Aes128);
        let stray = Crypto::new_initiator(config(KeyLength::Aes128)).kmreq().unwrap();
        assert_eq!(caller.handle_kmrsp(&stray), KmRspOutcome::Ignored);
        assert_eq!(caller.snd_km_state(), KmState::Secured);
    }

    #[test]
    fn kmrsp_malformed_is_ignored() {
        let mut initiator = Crypto::new_initiator(config(KeyLength::Aes128));
        for len in [0usize, 1, 3, 5] {
            assert_eq!(
                initiator.handle_kmrsp(&vec![0u8; len]),
                KmRspOutcome::Ignored,
                "len {len}"
            );
        }
        assert_eq!(initiator.snd_km_state(), KmState::Securing);
    }

    #[test]
    fn kmrsp_status_state_table() {
        // §6.3 table; §5.1 trap: the status word is little-endian.
        let cases: [(&[u8; 4], KmState, KmState, KmState); 5] = [
            // wire word (LE)      outcome              snd                  rcv
            (&[4, 0, 0, 0], KmState::BadSecret, KmState::BadSecret, KmState::BadSecret),
            (&[3, 0, 0, 0], KmState::NoSecret, KmState::NoSecret, KmState::Unsecured),
            (&[0, 0, 0, 0], KmState::Unsecured, KmState::Unsecured, KmState::NoSecret),
            // "anything else": a known-but-nonsensical state...
            (&[1, 0, 0, 0], KmState::NoSecret, KmState::NoSecret, KmState::NoSecret),
            // ...and BADSECRET's big-endian bytes = unknown word 0x04000000
            // — an implementation reading BE would confuse the two rows.
            (&[0, 0, 0, 4], KmState::NoSecret, KmState::NoSecret, KmState::NoSecret),
        ];
        for (wire, outcome, snd, rcv) in cases {
            let mut initiator = Crypto::new_initiator(config(KeyLength::Aes128));
            assert_eq!(
                initiator.handle_kmrsp(wire),
                KmRspOutcome::Failed(outcome),
                "wire {wire:?}"
            );
            assert_eq!(initiator.snd_km_state(), snd, "wire {wire:?}");
            assert_eq!(initiator.rcv_km_state(), rcv, "wire {wire:?}");
            // §6.3: an error report zeroes the retries — no more resends.
            assert!(
                initiator.on_ack(Instant::now(), 100_000).is_none(),
                "wire {wire:?}"
            );
        }
    }

    #[test]
    fn kmrsp_unsecured_gates_on_ack_entirely() {
        // §11.2: `sendKeysToPeer` skips when SndKmState == UNSECURED; the
        // refresh machine must not run for a peer without crypto.
        let (mut caller, mut listener) =
            kmx_pair_with(refresh_config(), config(KeyLength::Aes128));
        assert_eq!(
            caller.handle_kmrsp(&[0, 0, 0, 0]),
            KmRspOutcome::Failed(KmState::Unsecured)
        );
        let t0 = Instant::now();
        for n in 1 ..= 20 {
            roundtrip(&mut caller, &mut listener, n);
            assert!(caller.on_ack(t0, 100_000).is_none(), "packet {n}");
        }
    }
}
