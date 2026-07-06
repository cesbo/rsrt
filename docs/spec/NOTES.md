# Spec verification notes

Verification pass over `packets.md`, `handshake.md`, `transmission.md` against the
**libsrt v1.4.4 tag sources** (fetched from `github.com/Haivision/srt` at tag
`v1.4.4`: `core.{h,cpp}`, `handshake.{h,cpp}`, `packet.{h,cpp}`, `common.{h,cpp}`,
`queue.{h,cpp}`, `crypto.{h,cpp}`, `api.cpp`, `socketconfig.h`, `congctl.{h,cpp}`,
`buffer.{h,cpp}`, `tsbpd_time.{h,cpp}`, `list.cpp`, `window.{h,cpp}`,
`utilities.h`, `channel.cpp`, `sync.cpp`, `srt.h`, `apps/transmitmedia.cpp`;
`master` consulted only to date-stamp one bug). Every constant, mask, CIF length,
state-machine step and timer in the three docs was checked; the docs agree with
each other everywhere they overlap. Findings below.

---

## 1. Errors found and fixed (docs edited in place)

1. **Cookie tolerance is a 1.4.4 bug, docs had it backwards** (`handshake.md` §6,
   §5.3, §11.6). 1.4.4's fallback is `bake(addr, cookie, -1)` with
   `t = minutes + distractor − correction` → `correction = −1` computes the
   **next** minute's cookie, not the previous one (comment says "earlier"; sign
   fixed in later libsrt, where the formula is `+ correction`). Effective 1.4.4
   behavior: only the current-minute cookie validates; a handshake that straddles
   the listener's minute rollover between INDUCTION and CONCLUSION is silently
   ignored until the caller's 3 s timeout. Docs now describe this and mandate
   current-or-previous-minute acceptance for our listener (listener-local, so
   interop-neutral).

2. **In-stream KMREQ: default libsrt sends NO KMRSP** (`packets.md` §5.10,
   `transmission.md` §12). Verified in `processSrtMsg`/`crypto.cpp`: with the
   default `SRTO_ENFORCEDENCRYPTION=true`, a failed in-stream KMREQ yields
   `res = SRT_CMD_NONE` ("rejecting per enforced encryption") — **no reply**, the
   connection stays up, KK≠0 data is dropped. Only permissive mode
   (`ENFORCEDENCRYPTION=false`) replies with the one-word KMRSP. The one-word
   payload itself is now byte-confirmed (`HSv4_ErrorReport`: `srtlen = 1`,
   `word[0] = m_RcvKmState`, e.g. `SRT_KM_S_NOSECRET = 3`, big-endian). The doc
   previously recommended sending KMRSP(NOSECRET) as "maximally compatible" —
   flipped: 1.4.4-faithful behavior is *ignore + drop encrypted data*.

3. **Listener CONCLUSION-processing order** (`handshake.md` §5.3):
   `CHandShake::valid()` runs **before** the cookie check (doc had them swapped).
   Externally invisible (both are silent ignores) but the doc presents an exact
   order. Also added the missing "payload ≥ 48 bytes" gate to step 1.

4. **`processCtrlAck` initial-RTT gate imprecise** (`transmission.md` §6.9): libsrt
   adopts the peer's RTT/RTTVar only when **both** differ from the 100 000/50 000
   initial pair (`rtt != INITIAL_RTT && rttvar != INITIAL_RTTVAR`); the doc's
   "unless they still equal the initial pair" implied both-must-equal to skip.

5. **`BrokenCounter = 60` semantics resolved** (`transmission.md` §11): GC thread
   ticks every 1 s; `checkBrokenSockets` decrements the counter once per tick
   *only while unread data remains in the receive buffer*. So a broken socket with
   pending data lingers up to ~60 s; without pending data it closes at the next
   tick. (Peer-idle break uses 30, attack-breaks use 0 — app-local only.)

6. **Timer cadence under total silence resolved** (`transmission.md` §10):
   `CChannel::recvfrom` uses a `select()` timeout of exactly 10 000 µs, so the
   rcv-queue worker wakes at least every 10 ms even with no traffic; the "at least
   every ~10 ms" guidance is now stated as confirmed, not hedged.

7. **Message-number wrap precision** (`packets.md` §3.2): in the live path
   (`RollNumber` increment) values run `1..0x03FF_FFFF` **inclusive**, then wrap
   to 1. (The doc previously said reaching `0x03FF_FFFF` triggers the reset —
   that's the file-path behavior only.)

8. **ACKACK throttle operator** (`packets.md` §5.3.1/§8): strictly `> 10 ms`, not
   `≥` (matches `transmission.md`, which already had `>`).

9. **`srt-live-transmit` options** (`handshake.md` §10): it sets `SRTO_SNDSYN=false`
   too (output side), and it never sets `SRTO_TSBPDMODE=true` — it only sets it to
   *false* when the URI has `tsbpd=false`; the default true comes from the library.

10. **Big-endian Peer-IP note upgraded from UNCONFIRMED to source-verified**
    (`handshake.md` §2.2, §UNCONFIRMED list): `CIPAddress::ntop` does
    `ip[0] = sin_addr.s_addr` (raw load → host-endian-dependent wire word for
    IPv4) and byte-explicit little-endian assembly for IPv6 (endian-independent).
    Only runtime testing on BE hardware remains undone; irrelevant for LE targets.

11. **Caller version check precision** (`handshake.md` §5.2): libsrt accepts any
    induction-response version `> 4` as HSv5-capable (not `== 5` exactly).

## 2. Open questions resolved without doc changes (claims were already correct)

- **CONCLUSION dst-ID = 0 is mandatory, and non-zero is NOT tolerated** — now
  fully code-resolved: `CRcvQueue::worker` routes `id != 0` to
  `worker_ProcessAddressedPacket` → hash lookup of *connected* sockets (the
  listener is registered separately, never in that hash) → unknown id is stashed/
  dropped via `worker_TryAsyncRend_OrStore`, never reaching
  `worker_ProcessConnectionRequest`. A non-zero-dst CONCLUSION can never create a
  connection on a 1.4.4 listener.
- **Small ACK** — exact emission condition confirmed (`sendCtrlAck`: timer fired
  but `now − m_tsLastAckTime <= m_tdACKInterval` → 16-byte CIF); it carries a real
  incremented ACK number, is stored in the ACK window, and gets an ACKACK. Only
  its real-world *frequency* remains unmeasured (see §3).
- **Socket-ID generator** — confirmed in `api.cpp`: seed `genRandomInt(1,
  MAX_SOCKET_VAL)` (closed range), allocation takes generator−1 (decreasing),
  rollover to MAX when ≤ 0, so 0 is never assigned; reserved-0 dispatch confirmed.
- **Induction request Extension Field = 2 unchecked by 1.4.4** — confirmed: the
  induction branch of `processConnectRequest` never reads `m_iType`; the
  `UDT_DGRAM` check exists only in the HSv4 CONCLUSION path.
- **Congestion Warning** — confirmed: never sent; on receive
  `interval = interval·1125/1000`. Mimicry remains optional guidance.
- **Sender TLPKTDROP sends no DROPREQ in 1.4.4** — confirmed (`checkNeedDrop` has
  no `sendCtrl(UMSG_DROPREQ)`); DROPREQ appears only from `processCtrlLossReport`
  (stale-range reply) and `packLostData` (negative offset / TTL-dropped message).
- **Bidirectional RTT double-smoothing bug** — confirmed verbatim:
  `avg_iir<4>(crttvar, abs(crtt − crtt))` and `avg_iir<8>(crtt, crtt)` (no-ops
  that decay RTTVar to 0). Do-not-reproduce guidance stands.
- Everything else spot-checked and exact, including: all header/flag masks and
  enum values, PB/KK/O/R bit positions, 26-vs-27-bit msgno, NAK MSB-range
  encoding and the sender's break-connection validations, Light/Small/Full ACK
  CIF lengths (4/16/24-28/32) and parsing gates, ACK journal start at 1, buffer
  floor 2, `0x4A17` magic, HSREQ flag bits and `0xBF` default, latency halves
  (RCV = upper 16 bits, first on wire), extension TLV layout and emission order,
  SID ≤ 512 + per-word byte reversal (`ItoHLA`), KM natural byte order
  (`HtoNLA`/`NtoHLA` pre-swap), rejection-code space (`>1000` strict), ISN
  echo/adoption, MSS `min()`, 48-byte CIF layout, 250 ms/3 s handshake timers,
  10 ms ACK / 20 ms-floor NAK / 1 s keepalive / 5 s + EXP>16 idle-break timers,
  FASTREXMIT formula and its dormancy, TLPKTDROP `max(...)+20 ms` threshold,
  TSBPD wrap (30 s window, `+2^32` commit, carryover rule) and drift
  (1000-sample batches, ±5 ms clamp), `CSeqNo` arithmetic, LiveCC pacing
  (`(avg_payload+44)/MAXBW`, `BW_INFINITE = 125 MB/s`), probe pairs
  (`seq & 0xF == 0`), and the 4-byte `m_extra_pad` list.

## 3. Remaining genuinely-unconfirmed items

1. **Live-wire capture verification** — all draft-vs-libsrt conflict resolutions
   (induction-response CIF socket ID, dst-ID 0, magic warn-only, echoed cookie,
   peer-IP semantics) are code-verified against the v1.4.4 tag but not yet
   packet-capture-verified against a running `srt-live-transmit`; the planned
   interop stage should still do this.
2. **Small-ACK frequency in the wild** — the emission condition is exact, but how
   often OS scheduling jitter actually triggers it was not measured. Receivers
   must parse it regardless; never emitting it is safe.
3. **Non-1.4.4 peers validating the induction Extension Field (2)** — other
   implementations not audited. Send `2` always.
4. **Big-endian host runtime behavior** for the IPv4 peer-IP word — code is
   unambiguous (see §1.10) but no BE build was executed. Irrelevant for LE.
5. **`srt-live-transmit` app-level chunking internals** — socket options audited
   (`transmitmedia.cpp`); its media read-loop chunk sizing beyond
   `SRTO_PAYLOADSIZE`-driven defaults (1316) was not separately audited.
   Handshake/protocol-invisible.
6. **HSv4-peer scope decision** — rejecting HSv4 CONCLUSION with 1008 is a
   deliberate non-conformance (a real 1.4.4 listener would accept HSv4 callers).
   Unchanged; just remember it if an HSv4 device ever shows up.

## 4. Implementer traps (interop with libsrt 1.4.4)

- **Send dst-ID 0 in BOTH handshake requests.** The draft's "use the ID from the
  induction phase" in CONCLUSION mis-routes the packet inside libsrt and the
  connection never forms (§2 above). Symmetrically, as listener, route *all*
  dst-ID-0 packets to connection-request handling and everything else by socket-ID
  + source-address match.
- **Don't read the CIF `SRT Socket ID` of the induction response** — it's the
  caller's own ID echoed back, not the listener's. The peer ID is learned only
  from the CONCLUSION response.
- **The cookie is opaque to the caller: echo it verbatim.** As listener, beware
  the 1.4.4 minute-rollover bug when testing *against* a libsrt listener: a rare
  3 s connect timeout right at a minute boundary is expected 1.4.4 behavior, not
  your bug.
- **Byte order has three layers:** (1) every 32-bit word of header+CIF is
  big-endian; (2) *inside* the handshake CIF, string-ish fields (StreamID, Peer
  IP) are packed little-endian-per-word so their bytes appear reversed within each
  wire word; (3) KM material is pre-swapped so its bytes appear in natural order.
  Mixing these up produces "ERTS…"-style shuffled StreamIDs on the other side.
- **Latency half-words:** receiver-delay is the *upper* 16 bits (first on the
  wire), sender-delay the lower. Swapping them silently negotiates the wrong
  direction's latency.
- **A 4-byte ACK CIF is a Light ACK** — never attach the 4-byte zero pad to an
  ACK. Do attach it to KEEPALIVE/SHUTDOWN/ACKACK/CGWARNING/PEERERROR (20-byte
  packets) to match libsrt exactly; accept 16-or-20-byte forms on receive.
- **Small ACKs (16-byte CIF) carry a real ACK number and expect ACKACK** — the
  draft's "Type-specific Information = 0 for Small ACK" is wrong for libsrt.
- **Never ACK a sequence you haven't seen contiguously +1, and never NAK
  `lo > hi` or beyond the peer's highest sent** — libsrt hard-breaks the
  connection on both (attack heuristics). An off-by-one in ACK generation kills
  the session rather than degrading it.
- **Retransmissions must reuse the original sequence number AND original
  timestamp** (and set R=1). Restamping breaks the peer's TSBPD.
- **Mask DROPREQ's message number** (`& 0x03FF_FFFF`) — upper bits can carry
  garbage flags; msgno 0 means drop-by-range-only.
- **Expect no reply to an in-stream KMREQ from default-config libsrt** (enforced
  encryption suppresses KMRSP). Don't block waiting for KM state.
- **ISN rules:** listener adopts and echoes the caller's ISN (both directions
  start there); the caller aborts on mismatch. Generate your ISN in
  `[0, 0x7FFF_FFFE]` — the peer's `valid()` requires `ISN < 0x7FFF_FFFF`
  (libsrt's own generator is closed-range and can, astronomically rarely, emit
  the invalid maximum).
- **Timestamp wrap is not optional:** live streams die at ~71.5 min without the
  30 s wrap-period handling. Keep the timestamp a raw `u32`, do math in 64-bit.
- **Repeated CONCLUSIONs are normal** (lost response): every CONCLUSION on an
  existing connection must be re-answered with the same-shaped response, and data
  may start arriving before the caller ever sees that response.
- **KEEPALIVE gets no reply; any received packet is liveness.** Unknown control
  types are ignored but still refresh liveness (libsrt resets `EXPCount` before
  dispatching on type).
- **Flags `0x2005`-style mistakes:** in the CONCLUSION Extension Field, set only
  bits for blocks actually attached (HSREQ `0x1` mandatory; `ext_flags == 0` and
  bit-without-block are both ROGUE rejections).

## 5. Encryption traps

Full normative encryption spec: `encryption.md` (KM wire format, PBKDF2/key wrap,
CTR IV, KMX handshake flows, enforcement matrix, refresh state machine, traps).
Pointers only — details live there:

- **1-word error KMRSP is little-endian on the wire** (sender host order;
  BADSECRET = `04 00 00 00`) — `encryption.md` §5.1. This *corrects* §1.2 above
  and `packets.md` §5.10, which say "big-endian" (wire-verified against a real
  1.4.4 listener; `UNSECURED = 0` masks the difference).
- KM blob rides as raw natural-order bytes on both carriers; success-KMRSP is a
  byte-exact echo validated by `memcmp` — `encryption.md` §5, §6.3.
- PBKDF2 uses only the **last 8 bytes** of the 16-byte salt; dual-SEK wrap is
  even-key-first — `encryption.md` §4.
- IV = salt[0..13] with the BE seqno word XORed at bytes 10..13 — `encryption.md`
  §9.2.
- Encrypt once / retransmit ciphertext; undecryptable packets are ACKed then
  dropped at delivery (and sequence gaps they reveal are **never loss-detected
  or NAKed** — libsrt gates loss detection on decrypt success); KK=0 always
  delivered — `encryption.md` §9.3–9.4.
- A permissive failed-KMX responder with a passphrase sends an **unsolicited
  in-stream KMREQ** (fake KM) on the first ACK it receives, retried ×10 —
  `encryption.md` §6.2 step 6.
- Refresh: pre-announce at RR−PA (dual-SEK KMREQ), switch at RR, decommission at
  +PA, all evaluated on ACK receipt; mid-stream KMREQ applies to RX only; failed
  in-stream KMREQ gets **no reply** under default enforcement — `encryption.md`
  §10–11.
- Responder silently adopts the KMREQ's key length (never a KLen-mismatch
  reject); passphrase length is 10..**80** per code (docs say 79) —
  `encryption.md` §7, §2.
- **This implementation is always-enforced**: `SRTO_ENFORCEDENCRYPTION=false`
  (the `encryption.md` §8 permissive rows — 1-word status KMRSPs, fake TX
  contexts, unsecured connections on mismatch) is intentionally not
  implemented; every encryption mismatch rejects the connection at handshake
  time and a failed in-stream KMREQ gets total silence. Permissive peers
  still interop: the rejection happens before any data flows.
- Full checklist: `encryption.md` §15 "Traps".

## 6. Pacing/bandwidth audit — SRTO_MAXBW/INPUTBW/MININPUTBW/OHEADBW (v1.4.4)

Second verification pass, done while implementing LiveCC pacing and the
`Bandwidth` option (`transmission.md` §3.3.1–3.3.4). Every claim below was
re-checked against the v1.4.4 tag sources.

### 6.1 Confirmed against source

- **Setter ranges** (all reject with `SRT_EINVPARAM`): `SRTO_MAXBW >= -1`
  (socketconfig.cpp:226-236), `SRTO_INPUTBW >= 0` (291-300),
  `SRTO_MININPUTBW >= 0` (302-311), `SRTO_OHEADBW` in **5..=100** (313-322).
- **Defaults** `-1 / 0 / 0 / 25` (socketconfig.h:262, 275-277).
- **`updateCC` TEV_INIT mode resolution** (core.cpp:7294-7341):
  `MAXBW > 0` → fixed ceiling; `MAXBW == 0 && INPUTBW > 0` →
  `withOverhead(INPUTBW)` fixed; both 0 → in-buffer sampling requested.
  Includes the `only_input && llMaxBW` "don't change" guard: a runtime
  INPUTBW/OHEADBW change is ignored while MAXBW is set (core.cpp:7303-7307);
  a TEV_INIT_OHEADBW stage never resets the sampler (core.cpp:7322-7326).
- **Periodic ceiling refresh** — auto mode only, on TEV_ACK / TEV_LOSSREPORT /
  TEV_CHECKTIMER: `updateBandwidth(0, withOverhead(max(llMinInputBW,
  getInputRate())))` (core.cpp:7344-7364; the event sites: TEV_ACK
  core.cpp:8249, TEV_LOSSREPORT 8467, TEV_CHECKTIMER 10967).
- **`withOverhead`** = `(basebw·(100 + iOverheadBW))/100`, integer-truncating
  (core.h:656-659).
- **Estimator state machine** (buffer.cpp:299-333): first call stamps
  `m_tsInRateStartTime` only, bytes uncounted (305-309); strict comparisons on
  both closes — fast-start early close `pkts > INPUTRATE_MAX_PACKETS = 2000`
  (315), `elapsed > period` (318); +44·pkts (`SRT_DATA_HDR_SIZE`,
  packet.h:408-410) charged once at close (321); truncating division into
  bytes/s (322); on close the window restarts at the closing sample's time and
  the period switches to `INPUTRATE_RUNNING_US` = 1 s (326-330). Constants
  and the `BW_INFINITE` initial value: buffer.h:204-207, common.h:280.
- **Fed only from `addBuffer`** (buffer.cpp:277) — retransmissions
  (`readData`) never feed the estimator.
- **packData credit/reset/probe** (core.cpp:8966-9252): entry lateness accrued
  into `m_tdSendTimeDiff` when past the armed schedule (8978-8981); probe flag
  set only in the new-packet branch, `seq & PUMASK_SEQNO_PROBE == 0`
  (9098-9100; mask packet.h:215); idle reset (9106-9108) and window-blocked
  reset (9115-9117) both zero schedule AND credit; probe schedules the next
  send at `enter_time` with the credit untouched (9221-9226); the non-busy-
  wait spend-credit-or-wait tail (9231-9247).
- **TEV_SEND feeds only the avg-payload IIR**: `avg_iir<128>` over emitted
  payload lengths, rexmits included (`updatePayloadSize`, congctl.cpp:141-155,
  connected at 93); the interval copy-out excludes TEV_SEND / TEV_ACKACK /
  TEV_RECEIVE (core.cpp:7374-7379), so the IIR takes effect at the next rate
  event. Init: `SRTO_PAYLOADSIZE` (live default 1316) or `maxPayloadSize()`
  when 0 (congctl.cpp:79-82); ctor ceiling `BW_INFINITE` (congctl.cpp:77) and
  an immediate `updatePktSndPeriod` (congctl.cpp:89).
- **Lite and duplicate full ACKs never reach `updateCC`**: the lite-ACK short
  path returns first (core.cpp:8026-8042), the `m_iSndLastFullAck` gate
  returns on non-advancing full ACKs (8099-8105), `updateCC(TEV_ACK)` runs
  after both (8249).
- **cwnd re-pinned on every `setMaxBW`**: `m_dCWndSize = m_dMaxCWndSize`
  (congctl.cpp:196) — live mode never cwnd-throttles below the flow window.

### 6.2 Traps

- **`SRTO_OHEADBW` 0–4 is rejected**, not merely inadvisable — the libsrt
  docs' "avoid 0" guidance is moot; 5 is the real minimum.
- **The keep-previous-ceiling guard is not where the comment says.** The
  core.cpp:7353-7360 comment ("Keep previously set maximum in that case
  (inputbw == 0)") sits on `if (inputbw >= 0)` — vacuously true
  (`m_iInRateBps` inits to `BW_INFINITE` and is never negative,
  buffer.cpp:127). The behavior is real but lives in LiveCC:
  `updateBandwidth`'s `if (bw == 0) return;` (congctl.cpp:210-213), reachable
  only when the estimate is 0 AND `MININPUTBW == 0`.
- **Credit never survives idle or congestion**: any due slot with nothing
  sendable zeroes `SendTimeDiff` — a bursty app cannot bank catch-up credit
  across gaps.
- **A stale estimate persists through silence**: the rate only changes inside
  the submit-path feed; `SRTO_MININPUTBW` is the floor, and it acts **only in
  the auto path** (`MAXBW = 0, INPUTBW = 0`) — it never floors an explicit
  `INPUTBW`.
- **Probe pairs are NEW-packet-only**: the flag is set in the new-packet
  branch; a retransmission of a `seq & 0xF == 0` packet never probes (its
  *follower* slot may contain a rexmit, which the peer's estimator discards).
- **Three independent truncation points**: the window-close rate
  (buffer.cpp:322), `withOverhead` (core.h:658) and the whole-µs interval
  copy-out (core.cpp:7378) each truncate — exact-parity math must truncate at
  all three.
- **`updateInputRate` divides by a possibly-zero elapsed** (buffer.cpp:322):
  the `> 2000` early close can fire with all samples at one instant. Tripping
  it in libsrt takes over 2000 separate submit calls within one clock
  microsecond; a sans-I/O port whose establish-time flush submits a whole
  backlog with one `now` trips it deterministically — hence divergence D4
  below.

### 6.3 Divergences in this implementation (all spec-marked in transmission.md §3.3)

- **D1** — `Bandwidth::Unlimited` (default) disables the pacer structurally
  instead of gating at `BW_INFINITE`'s ~10.9 µs period (§3.3.2 divergence
  note). `Max { bytes_per_sec: 125_000_000 }` reproduces libsrt's literal
  default gate.
- **D2** — pacing mode fixed at connect; validation at `connect`/`bind`
  (`InvalidBandwidth`) instead of at `setsockopt` (same ranges, same
  rejection class). Consequence: the `Input` ceiling is computed once.
- **D3** — `AvgPayloadSize` init = `min(1316, max_payload)`: the crate has no
  `SRTO_PAYLOADSIZE` option (§3.3.1 divergence note); exact parity against
  default-configured libsrt at max payload ≥ 1316, and the IIR converges
  within ~128 packets regardless.
- **D4** — estimator zero-elapsed guard: a window never closes with
  `elapsed < 1 µs`; counters keep accumulating and the next distinct-instant
  submit closes normally (§3.3.3 simplification note).
- **S1** — ceiling refresh on every full ACK, not only sequence-advancing
  ones (idempotent; libsrt's own `checkTimers` refreshes at ≥ the same 10 ms
  cadence).
- **S2** — no `onRTO` recompute hook (congctl.cpp:158-163): the crate has no
  RTO/FASTREXMIT machinery (transmission.md §7.6 — dormant against 1.4.4
  peers anyway).
- **S3** — refresh cadence is full ACK + NAK + the sender's `on_timer`
  (pace/TLPKTDROP/keepalive deadlines) rather than per-received-packet
  `checkTimers`; the estimate changes at most once per sampling window, so
  the ceiling trajectory is identical at ≥ 10 ms granularity. The NAK
  refresh runs in ALL modes; in libsrt a loss report recomputes in auto mode
  only (no TEV_LOSSREPORT slot in LiveCC, congctl.cpp:93-100 — §3.3.1), so a
  fixed ceiling here picks up avg-payload IIR drift one event earlier.
