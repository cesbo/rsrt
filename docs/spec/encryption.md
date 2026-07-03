# SRT Encryption (HaiCrypt): AES-CTR, HSv5 Caller–Listener

Scope: SRT encryption as implemented by **libsrt 1.4.4** — live mode, HSv5
caller–listener only, AES-CTR cipher only (no GCM, no rendezvous, no file mode, no
preshared-KEK: srtcore always uses the passphrase secret type,
`socketconfig.cpp:CSrtConfigSetter<SRTO_PASSPHRASE>`).

Sources:

* libsrt **v1.4.4** tag sources (`haicrypt/`, `srtcore/crypto.{h,cpp}`, `core.cpp`,
  `packet.cpp`, `socketconfig.{h,cpp}`, `handshake.h`, `srt.h`). **This is the only
  normative source.** Citations are `file:function` into that tree (paths relative to
  the repo root; `crypto.cpp` = `srtcore/crypto.cpp`, HaiCrypt files under
  `haicrypt/`).
* IETF draft `draft-sharabayko-srt-01` §6 — consulted only to flag divergences
  (§14); **where it disagrees with libsrt 1.4.4, libsrt wins**.
* Facts marked **[wire-verified]** were confirmed against a live 1.4.4
  `srt-live-transmit` listener with a raw-UDP probe.

Companion docs: `handshake.md` (CIF layout, extension TLVs, rejection responses),
`packets.md` (data/control headers, KK bit positions), `transmission.md`
(ACK/TSBPD context for refresh timing).

---

## 1. Roles and key ownership

* In HSv5 caller–listener the **caller is always the KMX initiator** and the
  **listener the responder**, regardless of `SRTO_SENDER`
  (`core.cpp:startConnect` — "For HSv5, the caller is INITIATOR and the listener is
  RESPONDER"; `core.cpp:prepareConnectionObjects` maps the accepted socket to
  `HSD_RESPONDER`).
* **The caller generates the one SEK used in both directions.** At
  `crypto.cpp:CCryptoControl::init` the initiator (with a passphrase) creates the TX
  crypto context (defaulting PBKEYLEN 0→16), clones it TX→RX
  (`HaiCrypt_Clone(..., HAICRYPT_CRYPTO_DIR_RX, ...)`), and pre-generates the first
  KM message into send-slot 0 — *not sent yet*, it rides in the CONCLUSION handshake
  (`crypto.cpp:regenCryptoKm` called with `sendit=false`).
* **The responder creates nothing at init** ("Acceptor creates nothing - it will
  create appropriate contexts when receiving KMREQ from the initiator",
  `crypto.cpp:CCryptoControl::init`). On successfully unwrapping the KMREQ it clones
  its RX context into TX (`crypto.cpp:processSrtMsg_KMREQ`, the `bidirectional`
  branch), records the caller's KM message as its own send-slot 0 with retry
  counter 0 ("Don't start sending them upon connection"), and sets
  `SndKmState = SECURED`.
* The RX→TX clone happens **only** for handshake-carried KMREQ (`hsv > 4` ⇒
  `bidirectional`); a mid-stream refresh KMREQ is applied to the RX context only
  (§11.3). After the connection, each side refreshes its **own TX SEK**
  independently.
* Initial KM states (`crypto.cpp:CCryptoControl::init`): `RcvKmState = UNSECURED`;
  `SndKmState = SECURING` if a passphrase is set, else `UNSECURED`.

### 1.1 `SRT_KM_STATE` values (`srt.h`)

| value | name | meaning |
|---|---|---|
| 0 | `SRT_KM_S_UNSECURED` | no encryption |
| 1 | `SRT_KM_S_SECURING` | encrypted, KM exchange in progress |
| 2 | `SRT_KM_S_SECURED` | encrypted, KM exchanged, decrypting ok |
| 3 | `SRT_KM_S_NOSECRET` | peer encrypted but agent has no passphrase |
| 4 | `SRT_KM_S_BADSECRET` | agent has wrong passphrase (unwrap failed) |

---

## 2. Options and defaults

| Option | Values | Default | Effective value / notes | Source |
|---|---|---|---|---|
| `SRTO_PASSPHRASE` | empty (disable) or **10..80 bytes** | empty | Raw bytes, no NUL, no normalization. Reject `0 < len < 10` or `len > 80`. The `srt.h` comment says "10..79" — **the code accepts 80**; accept 10..80. | `socketconfig.cpp:CSrtConfigSetter<SRTO_PASSPHRASE>`; `haicrypt.h:HAICRYPT_SECRET_MAX_SZ`(=80) |
| `SRTO_PBKEYLEN` | 0, 16, 24, 32 | **0** | For an initiator with passphrase, 0 means **16** at context creation (`crypto.cpp:CCryptoControl::init`). See §7 for negotiation. | `socketconfig.cpp:CSrtConfigSetter<SRTO_PBKEYLEN>` |
| `SRTO_KMREFRESHRATE` | ≥ 0 packets | **0** | 0 → `HAICRYPT_DEF_KM_REFRESH_RATE = 0x1000000` (2^24) packets per SEK. Setting it force-sets pre-announce to `(RR−1)/2` when pre-announce is default or out of bounds. | `socketconfig.cpp:CSrtConfigSetter<SRTO_KMREFRESHRATE>`; `crypto.cpp:createCryptoCtx` |
| `SRTO_KMPREANNOUNCE` | ≥ 0, must satisfy `PA ≤ (RR−1)/2` | **0** | 0 → srtcore's `SRT_CRYPT_KM_PRE_ANNOUNCE = 0x10000` (2^16) — **not** HaiCrypt's own default `0x1000`, which is dead code under SRT. Out-of-range explicit value → option call fails. | `crypto.cpp` (const), `crypto.cpp:createCryptoCtx`; `socketconfig.cpp:CSrtConfigSetter<SRTO_KMPREANNOUNCE>` |
| `SRTO_ENFORCEDENCRYPTION` | bool | **true** | The `socketconfig.h` comment "Off by default" is stale — the initializer is `bEnforcedEnc(true)`. | `socketconfig.h` (CSrtConfig ctor); `socketconfig.cpp:CSrtConfigSetter<SRTO_ENFORCEDENCRYPTION>` |

HaiCrypt session config as filled by srtcore (`crypto.cpp:createCryptoCtx`):
`xport = HAICRYPT_XPT_SRT`, `key_len = PBKEYLEN`,
`data_max_len = HAICRYPT_DEF_DATA_MAX_LENGTH = 1500`, `km_tx_period_ms = 0`
(**no time-based KM injection — SRT drives KM sending itself**, §11),
`km_refresh_rate_pkt` / `km_pre_announce_pkt` per the table above.

---

## 3. KM message wire format

Assembled by `hcrypt_ctx_tx.c:hcryptCtx_Tx_AsmKM`; header bytes written by
`hcrypt_xpt_srt.c:hcryptMsg_SRT_ResetCache`. The KM message is a **byte string**:
all fields below are at fixed byte offsets, multi-byte fields big-endian by
construction (explicit byte stores). Layout (`hcrypt_msg.h`):

```
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
+0x00 |0|Vers |   PT  |             Sign              |    resv   |KF |
      +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
+0x04 |                              KEKI                             |
      +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
+0x08 |    Cipher     |      Auth     |      SE       |     Resv1     |
      +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
+0x0C |             Resv2             |     Slen/4    |     Klen/4    |
      +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
+0x10 |                              Salt                             |
      |                              ...                              |
      +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
      |                              Wrap                             |
      |                              ...                              |
      +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
```

| Offset | Size | Field | Value for SRT AES-CTR | Source |
|---|---|---|---|---|
| 0 | 1 B | S(1b)=0, Version(3b)=1, PT(4b)=2 (KM) → byte = **`0x12`** | fixed | `hcrypt_msg.h:HCRYPT_MSG_VERSION/HCRYPT_MSG_PT_KM`; `hcrypt_xpt_srt.c:hcryptMsg_SRT_ResetCache` |
| 1–2 | 2 B | Sign | **`0x20 0x29`** (`'HAI'` PnP Mfr ID, `('H'-'@')<<10 \| ('A'-'@')<<5 \| ('I'-'@')` = 0x2029, BE) | `hcrypt_msg.h:HCRYPT_MSG_SIGN` |
| 3 | 1 B | resv(6b)=0 + **KF/KK**(2b) | whole byte = `0x01` (even SEK), `0x02` (odd SEK), `0x03` (both) | `hcrypt_msg.h:HCRYPT_MSG_F_eSEK/oSEK`; `hcryptCtx_Tx_AsmKM` |
| 4–7 | 4 B | KEKI | **all zero** (passphrase mode; whole msg memset 0). RX never checks it. | `hcryptCtx_Tx_AsmKM` ("KEKI=0"); `hcrypt_ctx_rx.c:hcryptCtx_Rx_ParseKM` |
| 8 | 1 B | Cipher | **2** = `HCRYPT_CIPHER_AES_CTR` | `hcrypt_msg.h`; `hcryptCtx_Tx_AsmKM` |
| 9 | 1 B | Auth | **0** = `HCRYPT_AUTH_NONE` | ibid. |
| 10 | 1 B | SE (stream encapsulation) | **2** = `HCRYPT_SE_TSSRT` | ibid. |
| 11 | 1 B | Resv1 | 0 | memset |
| 12–13 | 2 B | Resv2 | 0 | memset |
| 14 | 1 B | Slen/4 | **4** (salt is always 16 B on TX) | `hcryptCtx_Tx_AsmKM` |
| 15 | 1 B | Klen/4 | **4 / 6 / 8** (AES-128/192/256) | ibid. |
| 16 .. 16+SLen−1 | SLen B | Salt | raw salt bytes | ibid. |
| 16+SLen .. end | 8 + n·KLen B | Wrap | RFC 3394 AES Key Wrap output (8-byte integrity block + n·KLen wrapped key bytes) | ibid. |

**Total length** = `16 + SLen + n·KLen + 8`, `n` = 1 (KK=01/10) or 2 (KK=11).
With SLen=16: single-key = **56/64/72 bytes**, dual-key = **72/88/104 bytes**
(KLen 16/24/32). Max = `HCRYPT_MSG_KM_MAX_SZ` = 104 = `SRT_CMD_MAXSZ`
(`crypto.h`). Always a multiple of 4.

Worked example — initial even-key KMREQ, KLen 16 (56 bytes):

```
12 20 29 01  00 00 00 00  02 00 02 00  00 00 04 04   header
<16 bytes salt>                                      CSPRNG
<24 bytes wrap>                                      RFC3394(KEK, eSEK): 8B ICV + 16B key
```

### 3.1 RX validation (`hcrypt_ctx_rx.c:hcryptCtx_Rx_ParseKM`)

In order; any failure ⇒ error (−1 ⇒ NOSECRET class, −2 ⇒ BADSECRET, §6.2):

1. `msg_len > 16`. (srtcore pre-checks `bytelen > 16` and `Klen != 0` and answers
   BADSECRET itself, `crypto.cpp:processSrtMsg_KMREQ`.)
2. `salt_len ≤ 16`, `sek_len ≤ 32`, and `sek_len ∈ {16, 24, 32}`.
3. Exact total length: `msg_len == 16 + salt_len + n·sek_len + 8`.
4. `Cipher == 2`, `Auth == 0`, `SE == 2`.
5. Carrier-layer pre-parse (`hcrypt_xpt_srt.c:hcryptMsg_SRT_ParseMsg`): runs
   **unconditionally as the first step of `hcrypt_rx.c:HaiCrypt_Rx_Process`**,
   i.e. **before** checks 1–4 (after srtcore's own pre-checks) and on **both
   carriers** — `crypto.cpp:processSrtMsg_KMREQ` feeds the HSv5 handshake-
   extension KMREQ (`core.cpp:interpretSrtHandshake`) and the in-stream
   `UMSG_EXT` KMREQ (`core.cpp:processSrtMsg`) through the same
   `HaiCrypt_Rx_Process` call. Checks: Version==1, PT==2, Sign==0x2029,
   **SE==2**, **KK≠0**. Any failure ⇒ −1 ⇒ NOSECRET class (§6.2) — e.g. a
   handshake-carried KMREQ with KF byte `0x00` or a wrong Sign is rejected
   here (under enforcement → `SRT_REJ_UNSECURE`, wire 1011) and never reaches
   `hcryptCtx_Rx_ParseKM`. Do **not** skip these checks for handshake-carried
   KM.
6. KEKI is **not** checked. **KLen is NOT compared with the local PBKEYLEN** (§7).

---

## 4. Key derivation and wrapping

### 4.1 Salt and SEK generation (TX)

* Salt: 16 bytes (`haicrypt.h:HAICRYPT_SALT_SZ`) from the CSPRNG (OpenSSL
  `RAND_bytes` — `cryspr-openssl.c:crysprOpenSSL_Prng`), generated by
  `hcrypt_ctx_tx.c:hcryptCtx_Tx_Rekey` at session creation.
* SEK: `key_len` bytes (16/24/32, validated `hcrypt.c:HaiCrypt_Create`) from the
  same CSPRNG.
* **Key refresh generates a new SEK only; the salt is carried over**
  (`hcrypt_ctx_tx.c:hcryptCtx_Tx_Refresh` copies `ctx->salt`), so a refresh
  re-runs neither PBKDF2 nor changes the IV nonce, on either side.

### 4.2 KEK derivation — PBKDF2 (`hcrypt_sa.c:hcryptCtx_GenSecret`)

```
KEK = PBKDF2-HMAC-SHA1( passphrase,
                        salt  = LAST 8 bytes of the KM Salt field,
                        iter  = 2048,
                        dkLen = KLen )        // KLen = SEK length 16/24/32
```

* PBKDF2 salt = `&salt[salt_len − 8]`, i.e. **salt bytes [8..15]** = KM message
  bytes [24..31] when SLen=16 (`pbkdf_salt_len = min(salt_len, 8)`; comment
  `KEK = PBKDF2(Pwd, LSB(64,Salt), Iter, Klen)`). Constants
  `HAICRYPT_PBKDF2_SALT_LEN 8`, `HAICRYPT_PBKDF2_ITER_CNT 2048` (`haicrypt.h`).
* Backing primitive: `PKCS5_PBKDF2_HMAC_SHA1`
  (`cryspr-openssl.c:crysprOpenSSL_KmPbkdf2`).
* **KEK length = SEK length**, so the wrap cipher is AES-128/192/256 matching KLen.
* Passphrase bytes are used verbatim (no NUL terminator, no normalization).
* RX re-derives the KEK only when the received salt bytes or KLen change
  (`hcrypt_ctx_rx.c:hcryptCtx_Rx_ParseKM`, `do_pbkdf` logic) — refreshes reuse it.

> **Divergence vs draft §6.1.4–6.1.5:** the draft never states that only the
> **last 8 bytes** of the 16-byte transmitted salt feed PBKDF2. Using all 16
> produces a wrong KEK and a guaranteed unwrap failure.

### 4.3 SEK wrapping — RFC 3394 AES Key Wrap

* Algorithm: AES Key Wrap with the **default IV `A6A6A6A6A6A6A6A6`**, keyed by the
  KEK. OpenSSL: `AES_wrap_key(kek, NULL, ...)` —
  `cryspr-openssl.c:crysprOpenSSL_KmWrap`; the in-tree fallback
  (`cryspr.c:crysprFallback_KmWrap`) implements the identical algorithm.
* Wrapped length = `8 + n·KLen` (integrity block + ciphertext).
* **Dual-key plaintext order: even SEK first, always** — "Even SEK first in dual
  SEK KMmsg", regardless of which key is the new one
  (`hcrypt_ctx_tx.c:hcryptCtx_Tx_AsmKM`). Both keys have the same length.
* Unwrap integrity failure (recovered IV ≠ `A6…A6`) is reported as **−2 =
  unmatched shared secret** (`hcrypt_ctx_rx.c:hcryptCtx_Rx_ParseKM`) ⇒
  `SRT_KM_S_BADSECRET` at srtcore (`crypto.cpp:processSrtMsg_KMREQ`). This is the
  **only** cryptographic wrong-passphrase detector in the protocol.

---

## 5. Carriers and byte order

The KM message travels on two carriers, byte-identical on the wire:

1. **HSv5 CONCLUSION handshake extension**, ext type `SRT_CMD_KMREQ = 3` /
   `SRT_CMD_KMRSP = 4`, Extension-Field bit `HS_EXT_KMREQ = 0x2` (`handshake.h`;
   TLV layout per `handshake.md` §4).
2. **In-stream `UMSG_EXT` control packet** (type `0x7FFF`), extended type 3/4 —
   in HSv5 used for key refresh (§11; "initial KMX is done still in the
   HS process in HSv5", `core.cpp:processCtrlUserDefined`) **and** for the
   unsolicited fake-KM KMREQ of a permissive failed-KMX responder (§6.2 step 6).

**Byte-order rule.** Every control-packet payload word is `htonl`-swapped at send
(`packet.cpp:CPacket::toNL`, applied by `channel.cpp:CChannel::sendto`) and
un-swapped at receive (`toHL`). Because the KM message is already a natural-order
byte string, libsrt **pre-swaps it once so the channel swap cancels out**:

* TX handshake ext: `core.cpp:fillHsExtKMREQ` / `fillHsExtKMRSP` (`NtoHLA`, comment:
  "this KM message is ALREADY in network order");
* TX `UMSG_EXT`: `core.cpp:sendSrtMsg` (`HtoNLA`, "Pre-swap to cancel it");
* RX both carriers: `crypto.cpp:processSrtMsg_KMREQ` / `processSrtMsg_KMRSP`
  re-swap after `toHL` ("Re-swap to cancel it").

**Normative:** serialize/parse the KM blob as **raw bytes exactly as in §3** —
never apply the per-word big-endian rule to it, on either carrier.
**[wire-verified]** (KM bytes appear on the UDP wire in natural order,
`12 20 29 …`).

### 5.1 Exception: the 1-word failure KMRSP is sender-host-endian (LE)

The error KMRSP payload (§6.2) is written as a **host-order integer**
(`pw_srtdata_out[SRT_KMR_KMSTATE] = m_RcvKmState`,
`crypto.cpp:processSrtMsg_KMREQ`; likewise `failure_kmrsp[] = {SRT_KM_S_UNSECURED}`
in `core.cpp:fillHsExtKMRSP` and the `memcpy` in `core.cpp:craftKmResponse`) and
then goes through the same cancelling double swap. Net effect: **the wire carries
the sender's host bytes — little-endian on every mainstream build**. BADSECRET =
`04 00 00 00`. **[wire-verified]** (a 1.4.4 listener answered a garbage KMREQ with
extension words `0004 0001 | 04 00 00 00`).

The receiver applies the same double swap and reads its own host-order word, so
same-endian hosts agree. To interop with stock libsrt we MUST **emit and parse
this word little-endian**.

> **Divergences:** (a) the draft depicts KM State as an ordinary big-endian field;
> (b) `packets.md` §5.10 currently says "big-endian like every control word" —
> **wrong**, superseded by this section (`handshake.md` §4.3's swap-cancellation
> note already implies the LE behavior). Note `UNSECURED = 0` is endian-invariant,
> which hides the quirk in the most common permissive case.

---

## 6. KMX in the HSv5 handshake

### 6.1 Caller (initiator) side

* The CONCLUSION request sets Extension-Field bit `0x2` and appends one
  `SRT_CMD_KMREQ` block per recorded KM slot (`core.cpp:createSrtHandshake`;
  KMREQ flag set whenever `CryptoSecret.len > 0 || kmdata_wordsize > 0`).
  Normally only slot 0 (even key) exists at connection time; two blocks occur only
  if a re-handshake overlaps a refresh window — out of scope for HSv5
  caller–listener, and the responder would process **only the first block** anyway
  (the KMREQ branch of `core.cpp:interpretSrtHandshake` breaks out of the
  extension loop after processing one).
* Handshake-time attachment does **not** decrement the KM retry counter
  (`crypto.h:getKmMsg_markSent` with `runtime=false` skips the decrement — but it
  still **unconditionally stamps `m_SndKmLastTime`**, the in-stream resend pacing
  clock; the stamp precedes the `runtime` check. No wire effect in HSv5
  caller–listener scope, since retries are zeroed when the connection completes)
  — the KMREQ is re-attached as long as the handshake itself is retried.
* On the CONCLUSION response the caller processes the KMRSP block
  (`core.cpp:interpretSrtHandshake` → `crypto.cpp:processSrtMsg_KMRSP`, §6.3).
  If that returns −1 **and `SRTO_ENFORCEDENCRYPTION=true`**, the caller **aborts
  locally with `SRT_REJ_UNSECURE`** — always UNSECURE, even when the failure was
  BADSECRET. **Nothing is sent to the listener**; the listener's accepted socket
  dies by its own timeout. (Design note: libsrt sends no SHUTDOWN here; mirror
  that — do not "helpfully" notify the listener.)

### 6.2 Listener (responder) side

Processing is fully synchronous inside CONCLUSION handling
(`core.cpp:acceptAndRespond` → `interpretSrtHandshake` → `crypto.cpp:
processSrtMsg_KMREQ`; the HSRSP and KMRSP are serialized into the **same**
CONCLUSION response packet). Steps of `processSrtMsg_KMREQ`:

1. `bytelen > 16` else `RcvKmState = BADSECRET`, 1-word reply; `Klen != 0` else
   same.
2. **Adopt the sender's key length**: `m_iRcvKmKeyLen = sek_len;
   m_iSndKmKeyLen = m_iRcvKmKeyLen` ("Overwrite the key length anyway"). Never an
   error (§7).
3. No local passphrase → `RcvKmState = NOSECRET`, 1-word reply.
4. Create RX crypto ctx, run `HaiCrypt_Rx_Process` (§3.1, §4):
   * OK → `RcvKmState = SECURED`; **reply = the whole received KM message echoed
     byte-for-byte** ("Send back the whole message to confirm");
   * unwrap failure (−2) → `Rcv = Snd = BADSECRET`, 1-word reply;
   * other error → `Rcv = Snd = NOSECRET`, 1-word reply.
5. On success (HSv5): clone RX→TX, adopt the caller's KM message as own slot 0
   with `iPeerRetry = 0` (§1).
6. On failure with a local passphrase (HSv5): create a **fake TX context**
   (`crypto.cpp:createFakeSndContext`, called from the `HSv4_ErrorReport` tail of
   `processSrtMsg_KMREQ`; the no-KMX permissive post-check path
   `core.cpp:interpretSrtHandshake` calls it too) so outgoing data is still
   encrypted — with a locally generated SEK the peer never receives; the peer
   drops those packets. **This is NOT wire-equivalent to marking TX unusable —
   the fake context also emits an unsolicited in-stream KMREQ.** Mechanism:
   `hcrypt.c:HaiCrypt_Create` leaves the fake even TX ctx with ANNOUNCE+TTSEND
   pending while send slot 0 is empty; on the **first ACK the responder
   receives** (i.e. as soon as it sends any data itself:
   `core.cpp:processCtrlAck` → `checkSndTimers(REGEN_KM)` →
   `crypto.cpp:sendKeysToPeer`, whose gate skips only
   `SndKmState == UNSECURED` — NOSECRET/BADSECRET pass) `regenCryptoKm` →
   `hcryptCtx_Tx_InjectKM` emits the fake KM, which differs from the empty
   slot-0 cache → cached, `iPeerRetry = 10`, and an **unsolicited `UMSG_EXT`
   `SRT_CMD_KMREQ` carrying the fake KM is sent immediately**, then retried per
   §11.2 (1.5×SRTT pacing) until a KMRSP (echo or 1-word error) arrives or
   retries exhaust. (A stock **permissive** libsrt peer — the only stock config
   that reaches rows 7/11 — replies with the 1-word error KMRSP, which zeroes
   the retries, §6.3/§11.2; a peer whose in-stream-KMREQ handling is
   **enforced** replies nothing, §11.3, and all 10 retries are spent.) On KMX
   *success* the same
   pending TTSEND fires too but is silently absorbed: slot 0 then holds the
   recorded peer KMREQ (step 5), and `hcrypt_ctx_tx.c:hcryptCtx_Tx_CloneKey` +
   `hcryptCtx_Tx_AsmKM` reassemble a **byte-identical** KM (same salt/SEK/KEK;
   RFC 3394 wrap is deterministic) → memcmp equal → nothing sent. Mirror the
   whole behavior: encrypted undecryptable data **plus** the unsolicited
   fake-KM KMREQ; and as initiator, expect such a KMREQ from a stock permissive
   libsrt responder (process it per §11.3).

Enforcement (`core.cpp:interpretSrtHandshake`, runs on the listener):

* KMREQ present, agent has no passphrase, **enforced** → reject
  `SRT_REJ_UNSECURE` (wire 1011). **[wire-verified]**
* KMREQ processing yielded a 1-word result, **enforced** → reject
  `SRT_REJ_BADSECRET` (1010) if `RcvKmState == BADSECRET`, else `SRT_REJ_UNSECURE`
  (1011). **[wire-verified]** No KMRSP is sent — the rejection response replaces
  the CONCLUSION response (see `handshake.md` §3.1).
* Agent has passphrase, caller sent **no** KMX at all, **enforced** → post-check
  "Agent declares encryption, but Peer does not" → reject `SRT_REJ_UNSECURE`.
* Non-enforced: connection proceeds; the CONCLUSION response carries the KMRSP
  block — full echo on success, the 1-word state on failure, or a 1-word
  **`UNSECURED` (0)** when the agent has a passphrase but no KMREQ arrived
  (`core.cpp:fillHsExtKMRSP`, which then sets `Snd=NOSECRET, Rcv=UNSECURED`).
  The KMRSP block is omitted entirely only when the agent has no passphrase *and*
  no KMREQ arrived (`core.cpp:createSrtHandshake`).

**Repeated CONCLUSIONs** (lost response): every repeated CONCLUSION is re-answered
via `core.cpp:craftKmResponse`: if the incoming HS has the KMX flag, it re-sends
the recorded echo from **slot 0**, or the recorded failure state
(`RcvKmState ∈ {NOSECRET, BADSECRET}`) as a 1-word KMRSP; KMX flag with
`UNSECURED` recorded state is an IPE → CONN_REJECT.

### 6.3 KMRSP processing on the initiator (`crypto.cpp:processSrtMsg_KMRSP`)

* **Full-length payload**: byte-compare (`memcmp`, length must match too) against
  recorded slot 0 first, then slot 1 (`crypto.h:getKmMsg_acceptResponse`).
  Match ⇒ `Snd = Rcv = SECURED`, that slot's retry counter zeroed, return 1.
  No match ⇒ `Snd = Rcv = BADSECRET`, return −1. **The KMRSP must be the exact
  received KMREQ bytes — any re-encoding that changes one byte breaks the
  association.**
* **1-word payload** (peer error report; both slots' retries zeroed first):

  | word | resulting states (agent) | return |
  |---|---|---|
  | `BADSECRET` (4) | `Snd = Rcv = BADSECRET` | −1 |
  | `NOSECRET` (3) | `Rcv = UNSECURED`, `Snd = NOSECRET` (peer can't read us) | −1 |
  | `UNSECURED` (0) | `Rcv = NOSECRET`, `Snd = UNSECURED` (peer has no crypto) | **0** |
  | anything else | `Snd = Rcv = NOSECRET` | −1 |

  Note return 0 for `UNSECURED`: an **enforced caller still connects** in that
  case (only −1 rejects at `core.cpp:interpretSrtHandshake`).

---

## 7. PBKEYLEN negotiation

* Advertisement: CIF Type word, upper 16 bits (`handshake.h:SRT_HSTYPE_ENCFLAGS`),
  value = keylen bits 5..3 (`SRT_PBKEYLEN_BITS`): 16→**2**, 24→**3**, 32→**4**,
  unset→0 (`handshake.h:SrtHSRequest::wrapFlags`). The listener advertises in the
  INDUCTION response (`core.cpp:processConnectRequest`); the caller in every HSv5
  handshake it serializes (`core.cpp:createSrtHandshake`).
* Caller-side adoption on the INDUCTION response
  (`core.cpp:checkUpdateCryptoKeyLen`): advertised 2/3/4 with local PBKEYLEN 0 →
  **adopt peer's value**; both set and different → peer wins unless the agent set
  `SRTO_SENDER`; advertised 0 → keep own; 1/5/6/7 → ignore (logged IPE).
* **The KMREQ's KLen always wins on the responder** (§6.2 step 2): mismatch with
  the local `SRTO_PBKEYLEN` is **never a rejection** — the responder silently
  adopts it for both directions; the unwrap alone decides success. Mirror this
  adoption for interop-identical behavior; do not enforce KLen == negotiated
  PBKEYLEN on RX.

> **Divergence:** the draft says the KM key length "MUST match" the handshake
> Encryption Field; libsrt neither checks nor rejects.

---

## 8. Enforcement decision matrix

C = caller, L = listener; "pw" = passphrase set; wire reject = Handshake Type
`1000 + code` in the response CIF (`handshake.md` §3.1). Default is enforced on
both sides.

| # | C | L | match | enforcement | outcome |
|---|---|---|---|---|---|
| 1 | – | – | n/a | any | No KMX blocks; connect; both sides `Snd=Rcv=UNSECURED`. |
| 2 | pw | – | n/a | **L enforced** | **Listener rejects** `SRT_REJ_UNSECURE` (1011): KMREQ flag but no local passphrase. **[wire-verified]** |
| 3 | pw | – | n/a | L permissive, C enforced | Listener accepts, 1-word KMRSP `NOSECRET`(3); **caller aborts locally** `SRT_REJ_UNSECURE`; listener's accepted socket times out. |
| 4 | pw | – | n/a | both permissive | Connect. Caller `Rcv=UNSECURED, Snd=NOSECRET`; listener `Rcv=NOSECRET, Snd=UNSECURED`. Caller→listener data goes out encrypted and is **dropped by the listener**; listener→caller is plaintext and works. |
| 5 | – | pw | n/a | **L enforced** | **Listener rejects** `SRT_REJ_UNSECURE` (1011) at the "Agent declares encryption, but Peer does not" post-check. |
| 6 | – | pw | n/a | L permissive, C enforced | Listener accepts (fake TX ctx, `Snd=NOSECRET, Rcv=UNSECURED`), sends 1-word KMRSP `UNSECURED`(0). **Caller aborts locally** `SRT_REJ_UNSECURE` — the response carries `HS_EXT_KMREQ` but the caller has no passphrase (`core.cpp:interpretSrtHandshake`). |
| 7 | – | pw | n/a | both permissive | Connect. Caller processes KMRSP(UNSECURED) → ret 0 → **no reject** (§6.3). Caller→listener plaintext works; listener→caller encrypted with an unshared key, dropped by the caller. |
| 8 | pw | pw | yes | any | Connect; KMRSP = full echo; both sides `Snd=Rcv=SECURED`; both directions use the caller's SEK. |
| 9 | pw | pw | **no** | **L enforced** | **Listener rejects** `SRT_REJ_BADSECRET` (wire **1010**). **[wire-verified]** |
| 10 | pw | pw | no | L permissive, C enforced | Listener accepts with 1-word KMRSP `BADSECRET`(4) (its states `Snd=Rcv=BADSECRET`, fake TX ctx). **[wire-verified]** Caller aborts locally with `SRT_REJ_UNSECURE` (not BADSECRET). |
| 11 | pw | pw | no | both permissive | Connect; both `Snd=Rcv=BADSECRET`; each side encrypts with its own key; **all data dropped by both receivers**. |

Notes:

* Caller-side enforcement is purely local (connect() fails; reason via
  `srt_getrejectreason`); no packet is emitted.
* In live mode a bad KM state never blocks sending — the `isSndEncryptionOK` gate
  exists only in the file/stream path (`core.cpp`); packets are dropped at the
  **receiver**.
* Enforcement never tears down an **established** connection (§11.3).
* Rows 7 and 11 (surviving connections where the listener has a passphrase but
  KMX failed or never happened): the listener's fake TX context additionally
  emits an **unsolicited in-stream KMREQ** on the first ACK it receives,
  retried up to 10× (§6.2 step 6). In rows 3/6/10 the caller aborts before
  sending data, so the listener never gets an ACK and the KMREQ never fires.

### 8.1 Crypto reject codes on the wire

`SRT_REJ_BADSECRET = 10` → Handshake Type **1010** (wrong passphrase, responder
only); `SRT_REJ_UNSECURE = 11` → **1011** (passphrase required or unexpected)
(`srt.h`, `handshake.h:URQFailure`). The rejection response is the caller's
CONCLUSION CIF echoed with `m_iReqType` replaced and no extension blocks
(`handshake.md` §3.1). **[wire-verified]** (0x3F2/0x3F3 observed).

---

## 9. Data packet encryption

### 9.1 KK bits (TX)

* Wire field: bits 3–4 of data-header word 1 (`packet.h:MSGNO_ENCKEYSPEC`,
  `EK_NOENC=0, EK_EVEN=1, EK_ODD=2`; see `packets.md` §3.2).
* Value = the active TX context's flags (`crypto.h:getSndCryptoFlags` →
  `hcrypt_tx.c:HaiCrypt_Tx_GetKeyFlags`): even ctx → `KK=01`, odd ctx → `KK=10`
  (`hcrypt.c:sHaiCrypt_PrepareHandle` fixes `ctx_pair[0]`=even, `[1]`=odd).
* **The first SEK of a connection is always the even key**
  (`hcrypt.c:HaiCrypt_Create` activates `ctx_pair[0]`); each refresh flips
  even↔odd.
* `getSndCryptoFlags() == −1` (passphrase set but no usable TX ctx) suppresses
  sending entirely (`buffer.cpp:CSndBuffer::readData`).

### 9.2 AES-CTR counter block (IV)

Constructed by `hcrypt.h:hcrypt_SetCtrIV` for both encrypt and decrypt:

```
iv[0..15] = 0
iv[10..13] = pki                      // 32-bit packet index
iv[0..13] ^= salt[0..13]              // 112-bit nonce; salt bytes 14..15 UNUSED
iv[14..15] = 16-bit block counter, starts at 0, not XORed with salt
```

| IV bytes | 0..9 | 10..13 | 14..15 |
|---|---|---|---|
| content | `salt[0..9]` | `salt[10..13] XOR pki` | `0x0000` |

* `pki` = the **32-bit big-endian header word 0** of the data packet — i.e. the
  Packet Sequence Number field as it appears on the wire (MSB always 0 for data)
  (`hcrypt_xpt_srt.c:hcryptMsg_SRT_GetPki` with `nwkorder=1` ⇒ `htonl`;
  `HCRYPT_MSG_SRT_OFS_PKI = 0`). No 64-bit extension, no wrap handling: after the
  31-bit seqno wraps, `pki` repeats — irrelevant at the default refresh rate
  2^24 < 2^31, but **never configure `SRTO_KMREFRESHRATE` ≥ 2^31** (keystream
  reuse).
* Keystream: AES-ECB over successive counter blocks; ciphertext = plaintext XOR
  keystream; **output length = input length, no padding**
  (`cryspr.c:crysprFallback_MsEncrypt`). The default OpenSSL path uses
  `CRYPTO_ctr128_encrypt` (whole-16-byte big-endian increment); the fallback
  increments only bytes 14–15. They diverge only for payloads ≥ 2^16 blocks
  (1 MiB); max SRT payload is 1456 B = 91 blocks, so **any stock AES-CTR with the
  IV above is byte-identical**.
* Only the payload is transformed; the 16-byte header stays clear
  (`HCRYPT_MSG_SRT_PFX_SZ = 16`).

> **Divergence:** draft §6.2.2 writes `IV = (MSB(112,Salt) << 2) XOR PktSeqNo` —
> wrong/ambiguous (the shift is 16 bits in reality and the ctr field is omitted).
> Use the byte layout above.

### 9.3 Encrypt once; retransmissions re-send ciphertext

TX pipeline (`core.cpp:packData`):

1. Application data sits in the send buffer as plaintext.
2. **First send**: sample `kflg = getSndCryptoFlags()`, OR the KK bits into the
   buffer block's stored msgno bitset (`buffer.cpp:CSndBuffer::readData`), fix
   seqno/timestamp/dst-ID, then encrypt **in place in the send-buffer block**
   (`crypto.cpp:CCryptoControl::encrypt` → `hcrypt_tx.c:HaiCrypt_Tx_Data`; the
   cryspr copies ciphertext back into the input buffer). The block now permanently
   holds ciphertext. `ctx->pkt_cnt++` per encrypted packet. If encryption fails
   the packet is **not sent** (`packData` returns error).
3. **Retransmission** (`core.cpp:packLostData`) re-reads the stored block: same
   bytes, same KK bits; only `PACKET_SND_REXMIT` (R bit) is added. The rexmit
   branch leaves `kflg = EK_NOENC`, so the encrypt step is **skipped** — never
   re-encrypt; the receiver decrypts a retransmission with the same (SEK, seqno).

**Normative:** encrypt exactly once at first transmission with the final wire
seqno in the IV; store ciphertext; retransmit byte-identical payload with the
original KK bits. Make "read active key + stamp KK + encrypt" atomic (libsrt has a
benign race between sampling `kflg` and encrypting — do not copy it).

### 9.4 RX decrypt path

Call site: `core.cpp:processData`, after the unit is inserted into the receive
buffer.

* **KK = 0** → `decrypt()` not even called; the packet is **delivered as
  cleartext**. libsrt 1.4.4 performs no enforcement against unencrypted packets on
  a secured link.
* **KK ≠ 0** → `crypto.cpp:CCryptoControl::decrypt`:
  * `RcvKmState == UNSECURED` + local passphrase → state → `SECURING`, drop
    ("surprise encryption": KMX still pending); no passphrase → state →
    `NOSECRET`, drop. Any state ≠ `SECURED` drops without attempting decryption.
  * Otherwise `hcrypt_rx.c:HaiCrypt_Rx_Data`: context chosen **purely by KK bits**
    — `ctx_pair[KK >> 1]` (KK=1→even, KK=2→odd; an illegal KK=3 data packet maps
    to the **odd** context — nothing rejects it on the SRT path; code-verified,
    not wire-tested). Selected ctx not KEYED → return 0 → drop. Ctx keyed →
    AES-CTR applied — **cannot fail and has no integrity check**: a
    wrong-but-installed key "succeeds" and delivers garbage.
  * Success: KK bits cleared to `EK_NOENC`; buffer holds plaintext.
* **On failure**, the packet:
  * stays in the receive buffer with KK bits set, **is ACKed**, advances the
    receive sequence — **no KM action, no connection action**
    (`core.cpp:processData`);
  * **suppresses loss detection for any sequence gap it reveals**: decrypt
    failure clears `adding_successful`, and the whole contiguity-check /
    loss-detection block — the only code that fills `srt_loss_seqs`, which
    feeds both `m_pRcvLossList->insert` and `sendLossReport` — runs only under
    `if (adding_successful)`; meanwhile `m_iRcvCurrSeqNo` is advanced
    **unconditionally** past the gap (`core.cpp:processData`). The skipped
    sequences never enter the receiver loss list and are **never NAKed** —
    neither immediately nor by later periodic loss reports. Wire-visible
    consequence to reproduce exactly: while incoming packets are undecryptable
    (mismatch rows 4/7/11 of §8, or a refresh window where the receiver lost
    the KMREQ and the sender switched at RR), a libsrt receiver emits **no
    LOSSREPORTs** for losses revealed by those packets;
  * is counted (`pktRcvUndecrypt`/`byteRcvUndecrypt` (+Totals), also folded into
    `pktRcvDrop` in `bstats`);
  * is **never delivered**: at read/TSBPD time any unit with crypto flags ≠ 0 is
    freed when its play time arrives (`buffer.cpp:getRcvReadyMsg` /
    `getRcvFirstMsg`) — the application sees a sequence gap, exactly like a TSBPD
    drop. TSBPD/ACK timing is otherwise unchanged.

Zero-length payloads: `cryspr.c:crysprFallback_MsEncrypt` returns −1 for
`out_len == 0`, which `packData` treats as encryption failure (packet not sent).
Live-mode SRT never produces empty payloads (`srt_sendmsg` rejects `len ≤ 0`);
do not encrypt empty payloads.

---

## 10. TX key-refresh state machine

Two contexts (even/odd) per direction, statuses
`INIT(1) SARDY(2) KEYED(3) ACTIVE(4) DEPRECATED(5)` (`hcrypt_ctx.h`). Per-context
`pkt_cnt`: set to **1** by the initial `hcryptCtx_Tx_Rekey`, to **0** by
`hcryptCtx_Tx_Refresh` for the pre-announced context, incremented per encrypted
packet (`hcrypt_tx.c:HaiCrypt_Tx_Data`).

### 10.1 Thresholds (`hcrypt_ctx_tx.c:hcryptCtx_Tx_ManageKM`)

`RR = refresh_rate`, `PA = pre_announce`, `cnt` = active ctx `pkt_cnt`. All
comparisons strict `>`; the branches are if / else-if / else-if (at most one
transition per invocation) **checked in this code order**:

| order | condition | action |
|---|---|---|
| 1. **Switch** | `cnt > RR` **or** `cnt == 0` (unsigned-rollover guard) | `Tx_Switch`: current → DEPRECATED, alt → ACTIVE, `crypto->ctx = alt`. Subsequent data packets carry flipped KK bits and the new SEK. |
| 2. **Pre-announce** | `cnt > RR − PA` **and** alt ctx not yet ANNOUNCE'd | `Tx_Refresh`: new SEK for alt ctx (salt, and hence KEK and IV nonce, unchanged); assemble **dual-SEK** KM message (new + current SEK, even key first in wire order); alt `pkt_cnt = 0`, status KEYED. Then `Tx_PreSwitch`: alt gets ANNOUNCE+TTSEND (KMREQ will be emitted); the current ctx's own announce is stopped since the dual KM covers it. |
| 3. **Decommission** | alt (= old) status == DEPRECATED **and** `cnt > PA` (`cnt` now counts the **new** key's packets since the switch) | `Tx_PostSwitch`: old ctx → SARDY, announce cleared; active ctx's cached KM reassembled **single-SEK**. No KM packet is emitted by this step (no TTSEND; `km_tx_period = 0` under SRT). |

Net wire behavior per cycle: one **dual-SEK KMREQ** at `RR − PA` packets (with
retries, §11.2), KK flip at `RR`, old key dead `PA` packets later. Effective
per-SEK usage ≈ `RR + PA`; both SEKs coexist ≈ `2·PA` packets around the switch.

*Quirks (do not reproduce, see Traps):* (a) a freshly switched ctx has
`pkt_cnt == 0` until the next data packet, so branch 1 can re-fire on an ACK that
arrives before any data is sent, flipping back to the deprecated key — harmless
since RX holds both keys; treat `cnt == 0` purely as the rollover guard. (b)
Because Switch is checked *before* Pre-announce, if more than `PA` packets are
sent between two ACKs, the switch can fire with an alt ctx that was never
rekeyed/announced (debug builds assert). A sane implementation evaluates
pre-announce first and never switches to a non-KEYED context.

### 10.2 When the machine ticks

`hcryptCtx_Tx_ManageKM` runs only via `HaiCrypt_Tx_ManageKeys` ←
`crypto.cpp:regenCryptoKm` ← `crypto.cpp:sendKeysToPeer(REGEN_KM)` ←
`core.cpp:checkSndTimers(REGEN_KM)` ← **`core.cpp:processCtrlAck`**. I.e.
**refresh decisions are made when ACKs are received** — thresholds are minimums;
the actual switch happens at the first ACK after the threshold is crossed. (The
rexmit-timer path calls `checkSndTimers(DONT_REGEN_KM)`, which only re-sends
pending KMREQs, initiator side, and never regenerates keys.)

### 10.3 KMREQ emission bookkeeping (`crypto.cpp:regenCryptoKm`)

Each KM message emitted by `hcrypt_ctx_tx.c:hcryptCtx_Tx_InjectKM` (TTSEND-gated,
flag cleared after inject) is keyed into send slot `ki = (key_flags & 3) >> 1` —
the KM **key index** (`crypto.cpp:regenCryptoKm`: `kix =
hcryptMsg_KM_GetKeyIndex(msg)`; `hcrypt_msg.h`: `(KF & HCRYPT_MSG_F_xSEK) >> 1`;
the code's subsequent `ki = kix & 0x1` is a no-op since `kix ∈ {0,1}`). So:
even-only KM (KF `0x01`) → **slot 0**; odd-only (`0x02`) → **slot 1**; dual-SEK
(`0x03`) → **slot 1**. (The initial even-key KMREQ therefore lives in slot 0,
consistent with §1 and §6.2 — the formula is *not* `key_flags & 1`, which would
invert the single-key cases.)
If the bytes differ from the cached slot: cache it, set
`iPeerRetry = SRT_MAX_KMRETRY = 10`, send immediately as `UMSG_EXT`+`SRT_CMD_KMREQ`,
stamp `m_SndKmLastTime`.

### 10.4 RX during refresh

Mid-stream KMREQ → `crypto.cpp:processSrtMsg_KMREQ` → `HaiCrypt_Rx_Process`:

* **Dedup**: a KM byte-identical to the **even context's** cache (with that ctx
  already KEYED) is not re-parsed — but srtcore still answers with the full
  **echo KMRSP** (`hcrypt_rx.c:HaiCrypt_Rx_Process`; retried KMREQs are
  idempotent and always re-acknowledged). Mechanism quirk: the dedup lookup
  indexes `ctx_pair` with `hcryptMsg_GetKeyIndex` = `getKeyFlags(msg) >> 1`,
  and the SRT-carrier `getKeyFlags` reads message bytes 4..7
  (`hcrypt_xpt_srt.c:hcryptMsg_SRT_GetKeyFlags`, `HCRYPT_MSG_SRT_OFS_MSGNO`=4)
  — for a KM message that is the **KEKI field, always 0** in passphrase mode —
  so the comparison target is **always the even context**, *not* the context
  `hcryptCtx_Rx_ParseKM` would select (code comment: "Even or Both SEKs check
  with even context"). Interop-neutral against libsrt peers (only single-even
  initial KMs and dual refreshes occur on the wire, and a dual install
  synchronizes both caches), but do not model the dedup as keyed to the
  flags-selected target context.
* **Dual-SEK install** (`hcrypt_ctx_rx.c:hcryptCtx_Rx_ParseKM`): target ctx =
  `crypto->ctx->alt` (the ctx *not* used by the last received data packet), or the
  ctx indexed by the message key-flags if no data seen yet. First wrapped SEK =
  even, second = odd (each ctx picks its half by its own flag); **both contexts
  are rekeyed from the one message**, both become KEYED, both share the
  salt/KM cache.
* **Both-keys window**: from the dual-SEK install until a later KM overwrites a
  slot, packets with either KK value decrypt — this tolerates late/retransmitted
  old-key packets around the switch.
* **No RX-side retirement**: a receiver key dies only by being overwritten by a
  later KM (≈ RR packets later). Never proactively expire an RX key slot.

---

## 11. Mid-stream KM: `UMSG_EXT` refresh KMX

### 11.1 Packet format (`core.cpp:sendSrtMsg`; `packet.cpp:CPacket::pack`)

| header word | content |
|---|---|
| 0 | bit 31 = 1; type = `0x7FFF`; bits 15..0 = extended type `SRT_CMD_KMREQ` (3) / `SRT_CMD_KMRSP` (4) → `0xFFFF0003` / `0xFFFF0004` |
| 1 | Type-specific Information — **always 0** (code-proven: `CPacket::CPacket` clears the header; the `UMSG_EXT` branch of `pack()` never writes word 1) |
| 2 | timestamp (µs since sender socket start) |
| 3 | destination socket ID (peer ID) |
| payload | KM message (KMREQ / echo KMRSP) or 1-word state (error KMRSP), byte order per §5; length multiple of 4 |

### 11.2 Sender behavior (`crypto.cpp:sendKeysToPeer`, on every received ACK)

* Skip if no TX ctx or `SndKmState == UNSECURED`.
* **Resend**: if any slot has `iPeerRetry > 0 && MsgLen > 0` and
  `now ≥ m_SndKmLastTime + 1.5 × SRTT`, resend that slot's KMREQ and decrement its
  retry (pacing ≈ 1.5·RTT; initial send + up to 10 retries).
* **Regen**: run the §10 machine; new/changed KM ⇒ slot update + immediate send.
* Retrying stops when: a KMRSP **echoing the exact bytes** arrives (that slot's
  retry → 0, both states → SECURED); or a 1-word error KMRSP arrives (**both**
  slots' retries → 0, states per §6.3, no connection consequence mid-stream); or
  retries are exhausted. **The sender switches to the new SEK at `RR` regardless**
  — a receiver that truly lost the KMREQ then drops every new-key packet; the
  connection only dies via the normal peer-idle timeout if all traffic stops.

### 11.3 Receiver behavior (`core.cpp:processSrtMsg`)

* `SRT_CMD_KMREQ` is processed with **hsv hardwired to 4** ⇒ `bidirectional =
  false` ⇒ the KM applies to the **RX context only** — never cloned to TX, even on
  an HSv5 connection. A successful refresh sets `RcvKmState = SECURED`
  (unconditionally — whatever the handshake-time result was) and re-arms the
  one-shot decrypt-error log.
* Response policy:
  * success → **full-echo KMRSP** via `UMSG_EXT`;
  * failure with **default `bEnforcedEnc = true` → NO RESPONSE AT ALL**
    (`res = SRT_CMD_NONE`, "rejecting per enforced encryption") — **the
    connection stays up**; enforcement never tears down an established
    connection;
  * failure with enforcement off → the 1-word failure KMRSP is sent.
* `SRT_CMD_KMRSP` → `processSrtMsg_KMRSP` (§6.3) with no connection consequences.
* An in-stream KMREQ is **not necessarily a refresh**: a permissive failed-KMX
  libsrt responder sends its fake KM this way right after the connection starts
  carrying responder→initiator data (§6.2 step 6). Same processing rules apply.

---

## 12. Defaults quick reference

| Constant | Value | Source |
|---|---|---|
| KM refresh rate (packets per SEK) | 2^24 = 0x1000000 | `haicrypt.h:HAICRYPT_DEF_KM_REFRESH_RATE` via `crypto.cpp:createCryptoCtx` |
| KM pre-announce (packets) | 2^16 = 0x10000 | `crypto.cpp:SRT_CRYPT_KM_PRE_ANNOUNCE` |
| KM in-stream retries | 10, paced 1.5 × SRTT | `crypto.cpp:SRT_MAX_KMRETRY`, `sendKeysToPeer` |
| PBKDF2 iterations / salt slice | 2048 / last 8 salt bytes | `haicrypt.h`, `hcrypt_sa.c:hcryptCtx_GenSecret` |
| Salt length (TX) | 16 bytes | `haicrypt.h:HAICRYPT_SALT_SZ` |
| Key wrap ICV | 8 bytes, RFC 3394 default IV `A6…A6` | `haicrypt.h:HAICRYPT_WRAPKEY_SIGN_SZ`, `cryspr.c` |
| PBKEYLEN default (initiator w/ pw) | 16 | `crypto.cpp:CCryptoControl::init` |
| Passphrase length | 10..80 bytes (0 = off) | `socketconfig.cpp`, `haicrypt.h` |
| Enforced encryption | on | `socketconfig.h` |
| KM message sizes | 56/64/72 single-key; 72/88/104 dual-key | §3 |
| First key | even (`KK=01`), ctx_pair[0] | `hcrypt.c:HaiCrypt_Create` |

---

## 13. Timing summary

* KMX is **synchronous inside CONCLUSION processing**: the listener's HSRSP and
  KMRSP ride in one CONCLUSION response packet; PBKDF2 + unwrap run inline
  (`core.cpp:acceptAndRespond`). **[wire-verified]**
* The caller interprets the KMRSP inside `postConnect`, before declaring the
  connection established.
* Refresh KMX is asynchronous and ACK-driven (§10.2, §11.2); no step of it ever
  blocks or breaks the connection.

---

## 14. Divergences from draft-sharabayko-srt-01 (all resolved in libsrt's favor)

1. **PBKDF2 salt**: last 8 bytes of the 16-byte salt only (§4.2); the draft
   implies the whole salt.
2. **1-word KMRSP endianness**: sender-host-order (LE in practice), not the
   big-endian field the draft draws (§5.1). **[wire-verified]**
3. **IV formula**: draft's `(MSB(112,Salt) << 2) XOR PktSeqNo` is wrong as
   written; see §9.2.
4. **Defaults**: draft recommends refresh 2^25 and pre-announce 4000; libsrt ships
   2^24 and 2^16 (§12).
5. **Decommission accounting**: draft says "at 2^25 + 4000" absolute; libsrt
   counts the *new* key's own packets past PA, evaluated lazily on ACKs (§10.1).
6. **Failed in-stream KMREQ**: draft implies a KMRSP reply; default (enforced)
   libsrt sends **nothing** and keeps the connection (§11.3).
7. **Caller-side enforcement failure code**: always local `SRT_REJ_UNSECURE`,
   even for a bad secret (§6.1).
8. **PBKEYLEN/KLen mismatch**: never an error — silently adopted (§7).
9. **Passphrase max length**: 80 per the code; `srt.h` and the draft say 79 (§2).
10. **Unspecified in the draft, normative from code**: encrypt-once/ciphertext in
    the send buffer with identical rexmit bytes (§9.3); undecryptable packets
    ACKed, counted, silently discarded at delivery, and loss detection is
    suppressed for gaps they reveal — no LOSSREPORT (§9.4); cleartext KK=0
    accepted on an encrypted link (§9.4); 10 retries at 1.5·RTT (§11.2);
    unsolicited fake-KM KMREQ from a permissive failed-KMX responder (§6.2
    step 6).

---

## 15. Traps (implementer checklist)

Byte-level:

* **KM blob = raw bytes on the wire; everything around it is per-word BE.** Do
  not word-swap the KM message; do word-swap the extension header word and the
  rest of the CIF (§5). Mixing these up shifts every KM field by a reversal.
* **The 1-word error KMRSP is little-endian on the wire** (sender host order):
  BADSECRET = `04 00 00 00`. `UNSECURED = 0` hides the bug — test with a nonzero
  state (§5.1). (`packets.md` §5.10 says "big-endian" — that is wrong;
  this section is normative.)
* **PBKDF2 salt = the LAST 8 bytes** of the 16-byte salt; KEK length = SEK
  length (§4.2).
* **Dual-SEK wrap order is even-first, always** — not "new key first" (§4.3).
* **IV**: seqno as a *big-endian 32-bit word* XORed at bytes 10..13; salt bytes
  14–15 never used; block counter starts at 0 (§9.2). Any stock AES-CTR works
  for SRT payload sizes.

KMX semantics:

* **Success-KMRSP is a byte-exact echo** of the received KMREQ; the initiator
  validates by `memcmp` (even slot first, then odd). Re-encoding = BADSECRET
  (§6.3).
* **A KMRSP mismatch or error never sends anything from the caller**: it aborts
  locally (always `SRT_REJ_UNSECURE`) and lets the listener's socket time out.
  Do not send SHUTDOWN (§6.1).
* **Wrong passphrase is only detectable via the RFC 3394 unwrap ICV** — there is
  no MAC anywhere else; with a wrong-but-installed key AES-CTR yields garbage
  silently (§9.4).
* **KLen from the KMREQ silently overrides local PBKEYLEN** on the responder —
  never reject on key-length mismatch (§7).
* **Passphrase: accept 10..80 bytes** (code-faithful), not the documented 79
  (§2). Local-only; not wire-visible.
* **Duplicate KMREQs must be re-echoed** (dedup still answers KMRSP) — the
  initiator's retries depend on it (§10.4).
* **Two KMREQ blocks in one handshake**: only the first is processed by a 1.4.4
  responder, and repeated-CONCLUSION responses echo slot 0 only. Moot for HSv5
  caller–listener (no re-handshake in scope) (§6.1, §6.2).
* **Permissive failed-KMX with a local passphrase creates a fake TX context**:
  data still goes out encrypted with a key the peer never got, **and an
  unsolicited in-stream KMREQ carrying the fake KM** goes out on the first ACK
  the responder receives, retried up to ×10 at 1.5×SRTT (a permissive peer's
  1-word error KMRSP stops the retries; an enforced peer replies nothing). Not
  equivalent to "TX unusable" (§6.2 step 6).
* **`UMSG_EXT` word 1 (Additional Info) = 0**; extended type lives in word 0's
  low half (§11.1).

Data path:

* **Encrypt once, store ciphertext, retransmit identical bytes** (original KK
  bits + R flag). Re-encrypting a retransmission desyncs nothing visibly — the
  bytes are simply wrong at the receiver for that seqno (§9.3).
* **KK routing on RX is mechanical**: KK=1→even slot, KK=2→odd slot, illegal
  KK=3→odd slot (no rejection); KK=0 bypasses decryption entirely and is
  **delivered as cleartext even on a secured link** (§9.4).
* **Undecryptable packets are ACKed** and silently dropped at delivery time —
  never NAK them, never take connection action, do count them. **Also never NAK
  a sequence gap revealed by one**: libsrt gates loss detection on decrypt
  success while advancing the receive cursor unconditionally, so such gaps are
  silently skipped and no LOSSREPORT is ever sent for them (§9.4).
* **Never encrypt a zero-length payload** — HaiCrypt reports it as failure
  (§9.4).

Refresh:

* **Evaluate refresh only on your ACK-processing path** (or a periodic sender
  tick), never per-packet; thresholds are strict `>` on per-key counters that
  start at **1** for the initial key and **0** for refreshed keys (§10).
* **Treat `pkt_cnt == 0` purely as a rollover guard** — libsrt's switch branch
  re-fires on it and flip-flops keys if an ACK lands before the first new-key
  packet (harmless there, confusing everywhere) (§10.1).
* **Check pre-announce before switch** (libsrt checks switch first and can, under
  pathological ACK gaps > PA packets, switch to a never-keyed context) (§10.1).
* **Mid-stream KMREQ applies to RX only** — never clone a refresh key into your
  TX direction (§11.3).
* **Expect no KMRSP for a failed in-stream KMREQ** from default-config libsrt;
  don't block on KM state, and keep the connection up regardless (§11.3).
* **The sender switches keys when the counter says so, not when the receiver
  confirms** — after 10 unanswered retries the new key is used anyway and the
  peer's packets just drop (§11.2).
* **Refresh reuses the salt**: no new PBKDF2, same IV nonce; only the SEK (and
  therefore the keystream) changes (§4.1).
