# SRT Live-Mode Data Transmission

Everything that happens on an established connection, after the handshake.

Interop target: **libsrt 1.4.4** (`srt-live-transmit`), HSv5, caller–listener, LIVE mode only.

Sources:

- Primary: IETF `draft-sharabayko-srt-01` (2021-09-07, the newest revision; expired,
  never published as an RFC), Sections 4.4–4.10, 5.1.
- Secondary (and normative where they differ): libsrt v1.4.4 sources —
  `srtcore/core.{h,cpp}`, `buffer.{h,cpp}`, `congctl.cpp`, `tsbpd_time.{h,cpp}`,
  `list.cpp`, `window.{h,cpp}`, `common.h`, `utilities.h`, `socketconfig.h`,
  `queue.cpp`. Every behavioral claim below was checked against the v1.4.4 tree.

Where the draft and libsrt 1.4.4 disagree, **libsrt 1.4.4 behavior is normative for
this implementation** and the difference is called out explicitly.

Wire formats (headers, ACK/NAK/DROPREQ CIF layouts, the 4-byte padding quirk) are in
the sibling `packets.md` — this document references them and covers *behavior*:
who sends what, when, and what the receiver of each packet must do.

Out of scope: handshake (sibling doc), encryption, rendezvous, file/messaging mode,
bonding, packet filter — mentioned only where they must be rejected/ignored.

---

## 1. Number arithmetic (used everywhere below)

### 1.1 Packet sequence numbers — mod 2^31, `CSeqNo`

31-bit values `0 .. 0x7FFF_FFFF` (`m_iMaxSeqNo = 0x7FFF_FFFF`), circular.
Comparison threshold `m_iSeqNoTH = 0x3FFF_FFFF`. Exact libsrt formulas
(`common.h`, all plain signed 32-bit int arithmetic):

```
seqcmp(a, b)  = (|a - b| < 0x3FFF_FFFF) ? (a - b) : (b - a)
                // > 0 means a is "later" than b

seqoff(a, b)  =  b - a                              if |a - b| < 0x3FFF_FFFF
              =  b - a - 0x8000_0000                else if a < b
              =  b - a + 0x8000_0000                otherwise
                // exact circular distance b - a (0x7FFF_FFFF + 1 = 0x8000_0000)

seqlen(a, b)  = (a <= b) ? (b - a + 1) : (b - a + 0x8000_0000 + 1)
                // inclusive length, precondition: a is not later than b

incseq(s)     = (s == 0x7FFF_FFFF) ? 0 : s + 1
decseq(s)     = (s == 0)           ? 0x7FFF_FFFF : s - 1
incseq(s, n)  = (0x7FFF_FFFF - s >= n) ? s + n : s - 0x7FFF_FFFF + n - 1
```

### 1.2 Message numbers — mod 2^26

26-bit (mask `0x03FF_FFFF`), start at **1**, wrap back to 1, `0` = "unknown"
(only meaningful in DROPREQ). See `packets.md` §3.2.

### 1.3 ACK numbers ("ACK journal") — `CAckNo`

Full 31-bit non-negative counter: `incack(a) = (a == 0x7FFF_FFFF) ? 0 : a + 1`.
Initialized to 0, incremented **before** sending, so the first ACK of a connection
carries ACK number 1. Not related to packet sequence numbers.

### 1.4 Smoothing filter `avg_iir`

`avg_iir<N>(old, sample) = (old*(N-1) + sample) / N` — integer division.
`avg_iir<8>` ≡ `7/8·old + 1/8·sample`; `avg_iir<4>` ≡ `3/4·old + 1/4·sample`.

---

## 2. Connection state right after handshake

Both sides know: own/peer Socket ID, ISN (identical in both directions in
caller–listener HSv5: the listener adopts the caller's ISN — `acceptAndRespond()`
sets `m_iISN = w_hs.m_iISN`), negotiated TSBPD latencies, peer's Flow Window size
(handshake "Maximum Flow Window Size" field, default `SRTO_FC` = **25600** packets),
max payload size.

Initial variables (`setInitialSndSeq/setInitialRcvSeq`, `CUDT` construction):

| Variable | Initial value | Meaning |
|---|---|---|
| `SndNextSeqNo` | ISN | next sequence to *schedule* (assigned at `srt_sendmsg2`) |
| `SndCurrSeqNo` | ISN − 1 | highest sequence *extracted/sent* on the wire |
| `SndLastAck` | ISN | first not-yet-ACKed seq (from peer's ACKs); flow-window base |
| `SndLastDataAck` | ISN | send-buffer release pointer (also advanced by sender TLPKTDROP) |
| `SndLastFullAck` | ISN | last full ACK processed (duplicate filter) |
| `SndLastAck2`, `SndLastAck2Time` | ISN, now | last ACK number answered with ACKACK + when |
| `FlowWindowSize` | peer's HS Flow Window field | live cap on in-flight packets |
| `RcvCurrSeqNo` | peer ISN − 1 | highest contiguity-tracked received seq |
| `RcvCurrPhySeqNo` | peer ISN − 1 | highest physically received seq (stats only) |
| `RcvLastAck` | peer ISN | next seq to be acknowledged (= receive-buffer base) |
| `RcvLastSkipAck` | peer ISN | receive-buffer base incl. TLPKTDROP skips |
| `RcvLastAckAck` | peer ISN | last ACK position confirmed by peer's ACKACK |
| `AckSeqNo` (journal) | 0 | last used ACK number |
| `SRTT` / `RTTVar` | 100 000 µs / 50 000 µs | `INITIAL_RTT` / `INITIAL_RTTVAR` |
| `EXPCount`, `ReXmitCount` | 1, 1 | liveness / rexmit escalation counters |

Buffers: send buffer default `SRTO_SNDBUF` = 8192 units, receive buffer
`SRTO_RCVBUF` = 8192 units (`DEF_BUFFER_SIZE`; one unit = one packet payload of up
to 1456 bytes). All per-packet state (seqno, msgno, origin time, rexmit time) lives
in these buffers.

> **Divergence (this implementation).** libsrt keeps the receive-buffer
> capacity fixed at the configured `SRTO_RCVBUF` even though the peer's
> handshake proposal can raise the effective TSBPD latency above the local
> setting (§9.1 max rule) — an undersized buffer then drops steadily at
> bitrates the configuration was thought to cover. Here the capacity is
> scaled with the negotiated latency to preserve the provisioned bitrate
> ceiling: `buffer_pkts = ceil(recv_buffer_pkts · negotiated/configured)`
> when negotiated > configured (configured floored at 1 ms). Growth is
> capped at 64× the provisioned capacity and 2²⁰ packets absolute — the
> peer controls the negotiated latency up to the wire cap (65 535 ms),
> and one far-offset datagram materializes the whole leading hole as
> `None` slots, so unbounded scaling would hand the peer control over
> per-connection memory. An explicit larger `recv_buffer_pkts` is never
> reduced (`scaled_recv_buffer` in core/mod.rs).

---

## 3. Data packet emission (sender)

### 3.1 Application submit (`srt_sendmsg2` → `CSndBuffer::addBuffer`)

1. Reject `len <= 0`. In live mode (LiveCC `checkTransArgs`) reject
   `len > payload size limit`: `SRTO_PAYLOADSIZE`, default **1316** in live mode
   (`SRT_LIVE_DEF_PLSIZE` = 7×188, MPEG-TS friendly), absolute max **1456**
   (`SRT_LIVE_MAX_PLSIZE` = 1500 MTU − 28 UDP/IPv4 − 16 SRT). **A live-mode message
   MUST fit in one packet** — there is no multi-packet message in live mode.
2. Run sender TLPKTDROP check (`checkNeedDrop`, §8.1) — this is where too-late
   packets are dropped, *on submit*, not on a timer.
3. If the send buffer has no room for the message: block (blocking mode) or
   `EAGAIN`/`SRT_EASYNCSND` (non-blocking).
4. Append to send buffer; assign per packet:
   - **Scheduling sequence number** = `SndNextSeqNo`, then
     `SndNextSeqNo = incseq(SndNextSeqNo)`. (One packet per message in live mode.)
   - **Message number** = `NextMsgNo` (starts at 1, +1 per message, wraps within
     26 bits back to 1). All packets of a message share it; in live mode every
     packet gets a fresh number.
   - **PP boundary flags**: packet `i` of an `n`-packet message gets
     `PB_FIRST` if `i==0` plus `PB_LAST` if `i==n-1` ⇒ live mode always
     `PB_SOLO` (`PP = 11b`).
   - **O flag**: from `SRT_MSGCTRL.inorder`, default false ⇒ `O = 0` in live mode.
   - **Origin time** = `steady_clock::now()` at submit, or the app-provided
     `srctime` (µs). An explicit `srctime` earlier than the socket start time is
     rejected with an error; `srctime` is only honored when TSBPD + message API are
     active (always true for live).
   - **TTL** = `SRT_MSGCTRL.msgttl`, default −1 (never expires). (If set ≥ 0, the
     message is dropped from the buffer when it fails to leave within TTL ms — §7.2.)

### 3.2 Wire emission (`CUDT::packData`, called by the send queue at paced times)

Priority order per send slot:

1. **Retransmission first**: `packLostData()` — if the sender loss list is
   non-empty, send a loss-list packet (§7). Retransmissions bypass the flow-window
   check.
2. (packet-filter control packet — out of scope, never in this implementation.)
3. **New packet**, only if window allows:
   `cwnd = min(FlowWindowSize, CongestionWindow)`;
   `flightspan = seqoff(SndLastAck, SndCurrSeqNo) + 1` (packets in flight; 0 when
   everything is ACKed, since then `SndLastAck == incseq(SndCurrSeqNo)`);
   send only if `cwnd > flightspan`. For LiveCC the congestion window is set to
   `MaxCWndSize` = the flow-window size at setup (initially 1000 before `TEV_INIT`,
   then = peer FC, 25600), i.e. **in live mode only the peer's advertised window
   actually constrains sending**.
   Then: extract next unsent packet from the buffer,
   `SndCurrSeqNo = incseq(SndCurrSeqNo)`, stamp it into the packet (in live mode
   scheduling seq == extraction seq).

Every data packet gets:

- **Timestamp** (header word 2): `(origin_time − socket_start_time) mod 2^32` µs
  (because peer TSBPD is on). If origin time somehow predates start time, `now` is
  used as fallback. **Retransmissions carry the ORIGINAL origin-time timestamp** —
  never the retransmission time; TSBPD depends on this.
- **Destination Socket ID** = peer's socket ID.
- **R flag** = 0 (first transmission) / 1 (retransmission).

### 3.3 Pacing (LiveCC)

#### 3.3.1 Send interval (PktSndPeriod)

- Inter-packet send interval (`updatePktSndPeriod`, congctl.cpp:173-181):
  `PktSndPeriod_us = 1e6 * (AvgPayloadSize + 44) / max_bw`
  where `AvgPayloadSize` = `avg_iir<128>` over *emitted* payload lengths — new
  transmissions AND retransmissions (the TEV_SEND hook, congctl.cpp:141-155) —
  init = config payload size (`SRTO_PAYLOADSIZE`, live default 1316, or the max
  payload size when 0; congctl.cpp:79-82); 44 = `SRT_DATA_HDR_SIZE`
  (28 UDP/IPv4 + 16 SRT header, packet.h:404-410); `max_bw` = the effective
  ceiling of §3.3.2 (with the default `SRTO_MAXBW = -1`: `BW_INFINITE` = 1 Gbps
  = 125 000 000 B/s ⇒ 10.88 µs, i.e. effectively unpaced at typical live
  bitrates).
- The interval is computed in floating point (`m_dPktSndPeriod`) but takes
  effect **truncated to whole µs**: the copy into `m_tdSendInterval` casts
  through `(int64_t)` (core.cpp:7374-7379). The double carries no cross-event
  state — it is fully re-derived from `AvgPayloadSize`/`max_bw` at each
  recompute, so a whole-µs representation is exactly equivalent.
- Recompute events, precisely: full ACK (TEV_ACK, via LiveCC's `onAck` slot)
  and the ≤ 10 ms `checkTimers` tick (TEV_CHECKTIMER, core.cpp:10967, via
  `onRTO`) — the only two slots LiveCC connects besides TEV_SEND
  (congctl.cpp:93-100). A loss report (TEV_LOSSREPORT) recomputes **in auto
  mode only**: there is no TEV_LOSSREPORT slot, so on a NAK the interval can
  change only through the auto-mode ceiling refresh
  (`updateBandwidth → setMaxBW → updatePktSndPeriod`, core.cpp:7344-7364,
  §3.3.2); with a fixed ceiling (`MAXBW > 0` or `INPUTBW > 0`) the copy-out
  merely re-copies the stale double and a NAK changes nothing until the next
  ACK/`checkTimers`. Light ACKs — and, in libsrt, non-advancing duplicate full
  ACKs (the `SndLastFullAck` gate, core.cpp:8099-8105) — return before
  `updateCC` and never recompute (core.cpp:8026-8042, 8249). TEV_SEND updates
  only the payload IIR, never the interval (excluded from the interval
  copy-out, core.cpp:7374). **This implementation** recomputes on NAK in all
  modes: for a fixed ceiling that only lets the interval pick up avg-payload
  IIR drift one event earlier than libsrt (bounded by the next ≤ 10 ms
  refresh either way).
- Retransmissions are paced under the same interval — they bypass the flow
  window (§3.2) only, NOT pacing — and never trigger probe pairs (§3.3.4).
- Unused send-slot time is *credited* (`SendTimeDiff`): if the sender fell behind,
  packets go out back-to-back until the debt is repaid (mechanics in §3.3.4).
- **Probe pairs**: a packet whose sequence satisfies `seqno & 0xF == 0` is followed
  by the next packet immediately (no pacing delay). The receiver measures link
  capacity on these pairs (§4.4).
- Sending anything refreshes the keepalive timer (`LastSndTime`).

**Divergence (this implementation):** the `AvgPayloadSize` IIR inits at
`min(1316, max_payload)` — this crate has no `SRTO_PAYLOADSIZE` option, so the
"config payload size" above does not exist here (D3, NOTES.md §6.3). Exact
parity against default-configured libsrt whenever the negotiated max payload
is ≥ 1316; below that the init is capped where libsrt would keep 1316, and
the IIR converges within ~128 packets regardless.

#### 3.3.2 Bandwidth ceiling resolution (SRTO_MAXBW / SRTO_INPUTBW / SRTO_MININPUTBW / SRTO_OHEADBW)

Defaults: `SRTO_MAXBW = -1`, `SRTO_INPUTBW = 0`, `SRTO_MININPUTBW = 0`,
`SRTO_OHEADBW = 25` (socketconfig.h:262, 275-277). Setter ranges, all rejected
with `SRT_EINVPARAM` outside: `MAXBW >= -1`; `INPUTBW`, `MININPUTBW >= 0`;
`OHEADBW` **5..=100** — 0–4 are not settable (socketconfig.cpp:226-236,
291-322). All rates are bytes/s and denote the *wire* budget (the §3.3.1
formula and the §3.3.3 estimator both charge +44 bytes/packet).

Exactly four configurations are reachable (`updateCC` TEV_INIT resolution,
core.cpp:7294-7341):

| Configuration | Effective ceiling `max_bw` (bytes/s) | Estimator |
|---|---|---|
| `MAXBW = -1` (default) | `BW_INFINITE` (125 000 000) | off |
| `MAXBW = n > 0` | `n`, fixed | off |
| `MAXBW = 0, INPUTBW = n > 0, OHEADBW = p` | `withOverhead(n)`, fixed | off |
| `MAXBW = 0, INPUTBW = 0, MININPUTBW = m, OHEADBW = p` | `withOverhead(max(m, estimate))`, refreshed | on (§3.3.3) |

- `withOverhead(b) = b·(100 + OHEADBW)/100` — integer-truncating division
  (core.h:656-659).
- Auto mode (last row) refreshes the ceiling on the §3.3.1 recompute events:
  `updateBandwidth(0, withOverhead(max(SRTO_MININPUTBW, estimate)))`
  (core.cpp:7344-7364). LiveCC `updateBandwidth(maxbw, bw)` semantics
  (congctl.cpp:199-216): `maxbw != 0` wins outright; else `bw == 0` ⇒
  **keep the previous ceiling** (`if (bw == 0) return;` — reachable when the
  estimate is 0 and `MININPUTBW = 0`); else adopt `bw`. `setMaxBW` maps any
  value ≤ 0 to `BW_INFINITE` (congctl.cpp:185).
- Every `setMaxBW` also re-pins the congestion window to the maximum
  (flow-window) size (congctl.cpp:196) — live mode never cwnd-throttles below
  the peer's flow window (§3.2).

**This implementation** exposes the four modes as one sentinel-free enum
(`Bandwidth` in `src/options.rs`):

| `Bandwidth` variant | libsrt equivalent |
|---|---|
| `Unlimited` (default) | `MAXBW = -1` |
| `Max { bytes_per_sec }` | `MAXBW = n > 0` |
| `Input { bytes_per_sec, overhead_pct }` | `MAXBW = 0, INPUTBW = n, OHEADBW = p` |
| `Estimated { min_bytes_per_sec, overhead_pct }` | `MAXBW = 0, INPUTBW = 0, MININPUTBW = m, OHEADBW = p` |

**Divergence (this implementation):** `Unlimited` disables the pacer
structurally instead of pacing at `BW_INFINITE`. libsrt's default still runs
the gate at a ~10.9 µs period — far below any achievable timer resolution and
indistinguishable on the wire below 1 Gbps sustained; disabling it keeps the
default path byte-identical to the pre-pacing implementation. Anyone wanting
libsrt's literal default gate sets `Max { bytes_per_sec: 125_000_000 }`.

**Divergence (this implementation):** the mode is fixed at connect time and
validated at `connect`/`bind` (`InvalidBandwidth`, same ranges as the
`SRT_EINVPARAM` rejections above). libsrt's four options are runtime-settable
(post-bind changes re-enter TEV_INIT with `only_input` stages,
core.cpp:384-401); this crate has no runtime option mutation, so the `Input`
ceiling is computed once and never re-derived.

#### 3.3.3 Sender input-rate estimation (CSndBuffer::updateInputRate)

Drives the auto (`Estimated`) mode only. State machine
(buffer.cpp:299-333):

- Fed **exclusively at application submit** (`addBuffer`, buffer.cpp:277):
  payload bytes, no headers. Retransmissions never feed it (`readData` has no
  feed), and it is never sourced from ACK words 4–6 (which this implementation
  sends as 0 — §4.4).
- The **first sample** after (re)start only stamps the window start; its bytes
  are NOT counted (buffer.cpp:305-309).
- The window closes on `elapsed > period` (strict, buffer.cpp:318) or on the
  fast-start early trigger `pkts > 2000` (strict, `INPUTRATE_MAX_PACKETS`,
  buffer.cpp:315). `elapsed` enters the comparison **truncated to whole µs**
  (`count_microseconds`, buffer.cpp:317) — a window effectively closes only
  once true elapsed reaches period + 1 µs, and the close division below uses
  the same truncated value. On close (buffer.cpp:321-330):
  `rate_Bps = trunc((bytes + pkts·44)·1e6 / elapsed_us)` — the +44/packet
  header charge is added once, at close; the window restarts at the closing
  sample's time.
- Window length: 500 ms fast-start (`INPUTRATE_FAST_START_US`) until the first
  close, 1 s (`INPUTRATE_RUNNING_US`) from then on (buffer.h:204-205).
- Initial value: `BW_INFINITE` (`INPUTRATE_INITIAL_BYTESPS`, buffer.h:207) —
  until the first window closes the auto ceiling is effectively unpaced
  (fast-start grace).
- The rate is recomputed **only** inside the feed: a stale value persists
  through arbitrarily long silence (`SRTO_MININPUTBW` is the operator's floor,
  and it acts in the auto path only — it never floors an explicit `INPUTBW`).

**First-implementation simplification (safe):** a window never closes with
`elapsed < 1 µs`. libsrt divides by a possibly-zero elapsed (buffer.cpp:322) —
firing the `> 2000` early close at zero elapsed would take over 2000 separate
submit calls within one clock microsecond there, but this crate's
establish-time flush of buffered-while-connecting packets submits up to 8192
packets with one identical `now` and trips it deterministically. When the
guard suppresses a close, counters keep accumulating and the next
distinct-instant submit closes normally.

**First-implementation simplification (safe):** the ceiling is refreshed on
*every* full ACK rather than only sequence-advancing ones (libsrt's
`SndLastFullAck` gate, §3.3.1) — the refresh is idempotent, and libsrt's own
`checkTimers` path refreshes at ≥ the same 10 ms cadence regardless.

**First-implementation simplification (safe):** there is no `onRTO` recompute
hook (congctl.cpp:158-163) — this crate has no RTO/FASTREXMIT machinery
(§7.6) — and the TEV_CHECKTIMER cadence is the sender's `on_timer` (pace /
TLPKTDROP / keepalive deadlines) rather than libsrt's per-received-packet
`checkTimers`. The estimate itself changes at most once per sampling window,
so the observable ceiling trajectory is identical at ≥ 10 ms granularity.

#### 3.3.4 Pacing gate (CUDT::packData scheduling)

Only the data send path paces; control packets are never gated (in libsrt only
the data send queue runs `packData`). Per send slot (core.cpp:8966-9252):

- **Entry lateness accrual**: if a next-send schedule is armed and `packData`
  enters past it, the overshoot is credited into `SendTimeDiff`
  (core.cpp:8978-8981).
- **Spend-credit-or-wait** (the non-busy-wait tail, core.cpp:9231-9247), after
  a data packet is emitted: if `credit >= interval`, the next send is due
  *now* (back-to-back catch-up) and `credit -= interval`; else the next send
  is due at `now + (interval − credit)` and `credit = 0`.
- **Idle/congested reset**: a due slot that finds nothing sendable — send
  buffer empty (core.cpp:9106-9108) or flow-window-blocked
  (core.cpp:9115-9117) — zeroes the schedule AND the credit. Credit never
  survives an idle or blocked state.
- **Probe exception**: a NEW packet whose `seq & 0xF == 0`
  (`PUMASK_SEQNO_PROBE`, packet.h:215; flag set only in the new-packet branch,
  core.cpp:9098-9100) schedules the next send at `now` with the credit
  untouched (core.cpp:9221-9226) — the follower goes out back-to-back for the
  peer's capacity estimator (§4.4). The follower may itself be a
  retransmission; the peer's estimator discards such pairs.

Sans-I/O mapping (this implementation): the armed next-send instant is
surfaced through the sender's `next_deadline()`, and the runtime's
deadline-batched drains realize the credit catch-up bursts — packets whose
schedules are `<= now` go out back-to-back within one drain turn, absorbing
the runtime's ~1 ms timer coarseness; no per-packet 10 µs sleeps are
attempted.

---

## 4. Receiver: ACK generation

Timers are evaluated per socket in the receive-queue worker: on every incoming
packet, and otherwise at least once per 10 ms (`COMM_SYN_INTERVAL_US = 10_000` µs).

### 4.1 When ACKs are sent (`checkACKTimer`)

- **Full ACK: every 10 ms** (`ACKInterval = COMM_SYN_INTERVAL_US`). None of the
  built-in congctls overrides the period or defines a packet-count trigger.
- **Light ACK**: between timer ACKs, when
  `PktCount >= 64 * LightACKCount` (`SELF_CLOCK_INTERVAL = 64`), send a light ACK
  and `++LightACKCount`. `PktCount` counts data packets received since the last
  timer-driven ACK (reset to 0 there, `LightACKCount` reset to 1) and is NOT reset
  by the light ACK itself ⇒ light ACKs fire after 64, 128, 192… packets within one
  ACK period. High-bitrate self-clocking supplement only.
- **Small ACK** (16-byte CIF): produced by the timer path when the ACK timer fires
  but < 10 ms passed since the last time the full-ACK payload was built. Rare
  (jitter). Parse it, don't bother sending it (send full 28-byte ACKs; libsrt
  accepts both).

### 4.2 What sequence number is acknowledged

```
ack = first sequence in the receiver loss list      // first missing packet
      if the loss list is non-empty
    = incseq(RcvCurrSeqNo)                          // last received + 1
      otherwise
```

I.e. **the ACK carries the sequence of the last contiguously received packet,
plus 1** (past-the-end of the fully received prefix).

Suppression rules, in order (`sendCtrlAck`):

1. If `ack == RcvLastAckAck` (peer already confirmed this position via ACKACK):
   send nothing.
2. Light ACK requested: send it now — CIF = `{ack}` (4 bytes), header
   Type-specific Info (ACK number) = **0**; no further state updates, no ACKACK
   expected. Done.
3. If `ack` is newer than `RcvLastAck`: `RcvLastAck = ack`,
   `RcvLastSkipAck = ack`, release the receive-buffer "ACK position" up to `ack`
   (this is what makes the data visible to TSBPD/application — see §9.5) and wake
   the TSBPD thread.
4. Else if `ack == RcvLastAck` (nothing new): repeat the ACK only if
   `now − LastAckTime >= SRTT + 4·RTTVar` µs (an un-ACKACKed position is re-announced
   at RTT cadence); otherwise send nothing.
5. Anything else (`ack` older than `RcvLastAck`) is an internal error — no send.
6. Final gate: only send if `RcvLastAck` is newer than `RcvLastAckAck`.

Then: `AckSeqNo = incack(AckSeqNo)`, build CIF, send, and store
`(AckSeqNo, RcvLastAck, now)` in the **ACK history window** (`ACK_WND_SIZE = 1024`
entries) for RTT lookup on ACKACK, `LastAckTime = now`.

### 4.3 Full ACK CIF fields the receiver must fill

Layout in `packets.md` §5.3. Semantics + estimators:

| Word | Field | How libsrt 1.4.4 computes it |
|---|---|---|
| 0 | Last ACK seq + 1 | §4.2 above |
| 1 | RTT (µs) | receiver-side smoothed RTT from ACK→ACKACK pairs (§5.2); 100 000 before first sample |
| 2 | RTTVar (µs) | ditto; 50 000 before first sample |
| 3 | Available buffer (pkts) | free units in receive buffer; **clamped to min 2** even when full (deadlock breaker) |
| 4 | Receive rate (pkts/s) | §4.4; 0 when unknown |
| 5 | Link capacity (pkts/s) | §4.4; 0 when unknown |
| 6 | Receive rate (bytes/s) | same estimator, byte counter; 0 when unknown |

### 4.4 Rate/capacity estimators (and allowed simplifications)

- **Receive rate**: arrival-interval window of the last **16** data packets
  (`CPktTimeWindow<16, 64>`). Take the median interval (`nth_element`), discard
  samples outside `(median/8, median*8)`; if more than 8 valid samples remain:
  `pkts_per_sec = ceil(1e6 / mean(valid intervals))`, and
  `bytes_per_sec = ceil(1e6 / (sum_us / (bytes_in_valid + 44*count)))`
  (44 = `SRT_DATA_HDR_SIZE` incl. UDP/IP overhead constant used by libsrt — it adds
  full protocol header size per packet); otherwise report **0**.
- **Link capacity**: window of the last **64** probe-pair intervals — the interval
  between arrival of packet `seqno & 0xF == 0` and the immediately following
  packet (pairs are rejected if either packet is retransmitted or out of order).
  Same median filter (the median itself is counted once extra);
  `capacity_pps = 1e6 / filtered_mean`.
- **First-implementation simplification (safe):** always send the 28-byte full
  ACK with words 4–6 = **0**. `0` is libsrt's own "no measurement yet" value; the
  1.4.4 sender feeds these into `avg_iir<8>` smoothers used only for statistics and
  FileCC decisions — LiveCC never reads them. Words 1–3 (RTT, RTTVar, buffer) MUST
  be real: word 0/3 drive the sender's flow window, words 1–2 feed the sender's
  RTT state (§6.3).

---

## 5. ACKACK and RTT computation

### 5.1 Sender side: reply to ACK with ACKACK

For every **non-light** ACK received (CIF ≥ 16 bytes), the data sender sends
ACKACK (control type `0x0006`), Type-specific Info = the ACK number being echoed,
no CIF (4-byte zero pad on the wire), immediately upon ACK receipt — throttled:
send only if

```
now − SndLastAck2Time > 10 ms   (COMM_SYN_INTERVAL_US)
OR ack_number == SndLastAck2    (same ACK number again ⇒ previous ACKACK lost)
```

then `SndLastAck2 = ack_number`, `SndLastAck2Time = now`.
Light ACKs (4-byte CIF, ACK number 0) never get an ACKACK.

**Divergence (draft vs libsrt):** the draft says ACKACK answers "full ACK";
libsrt 1.4.4 also answers 16-byte small ACKs (any non-lite ACK). Follow libsrt.

### 5.2 Receiver side: RTT from ACK→ACKACK (`processCtrlAckAck`)

1. Look up the echoed ACK number in the 1024-entry ACK history window:
   `rtt_sample = now − time that ACK was sent` (µs). Unknown/already-consumed ACK
   number ⇒ log and ignore (an entry is consumed by the lookup; out-of-order
   ACKACKs for older numbers are skipped). `rtt_sample <= 0` ⇒ ignore.
2. Update smoothed values — **first sample after connection setup**:
   `SRTT = rtt_sample; RTTVar = rtt_sample / 2`
   — **subsequent samples** (order matters, RTTVar first, using the old SRTT):

   ```
   RTTVar = avg_iir<4>(RTTVar, |rtt_sample − SRTT|)   // = 3/4·RTTVar + 1/4·|SRTT − rtt|
   SRTT   = avg_iir<8>(SRTT, rtt_sample)              // = 7/8·SRTT + 1/8·rtt
   ```

   Initial values before any sample: SRTT = 100 000 µs, RTTVar = 50 000 µs.
   (The draft gives the same 7/8 + 1/8 and 3/4 + 1/4 formulas; the first-sample
   reset is libsrt ≥ 1.4.4 behavior.)
3. Feed a TSBPD drift sample from the ACKACK's header **timestamp** (§9.4).
4. `RcvLastAckAck = max(RcvLastAckAck, acked seq from the window entry)` — stops
   redundant ACK repeats (§4.2 rule 1/6).

These receiver-side SRTT/RTTVar are what goes into ACK CIF words 1–2 and into the
receiver's own NAK/ACK-repeat periods.

---

## 6. Sender: processing an ACK (`processCtrlAck`)

Order of operations on receiving ACK with `ackseq` = CIF word 0:

1. `ackseq < 0` (MSB set — invalid) ⇒ ignore packet.
2. **Release the send buffer** (`updateSndLossListOnACK`, done for light and full
   ACKs alike): if `seqoff(SndLastDataAck, ackseq) > 0`:
   `SndLastDataAck = ackseq`; remove all sender-loss-list entries older than
   `decseq(SndLastDataAck)`; free that many packets from the front of the send
   buffer; unblock any waiting `srt_sendmsg2`/epoll-out.
3. **Light ACK** (CIF length exactly 4): if `seqcmp(ackseq, SndLastAck) >= 0`:
   `FlowWindowSize -= seqoff(SndLastAck, ackseq)`; `SndLastAck = ackseq`;
   refresh last-response-ACK time; `ReXmitCount = 1`. Done (no ACKACK).
4. **ACKACK decision** (§5.1).
5. **Sanity**: if `seqcmp(ackseq, incseq(SndCurrSeqNo)) > 0` — ACK for something
   never sent ⇒ **break the connection** (attack/bug; `m_bBroken = true`).
6. If `seqcmp(ackseq, SndLastAck) >= 0`:
   **`FlowWindowSize = CIF word 3`** (peer's available buffer, in packets);
   `SndLastAck = ackseq`; `LastRspAckTime = now`; `ReXmitCount = 1`.
7. Duplicate filter: if `seqoff(SndLastFullAck, ackseq) <= 0` ⇒ stop here
   (window/buffer already updated; RTT/rate fields skipped).
   Else `SndLastFullAck = ackseq`.
8. CIF length checks: `len % 4 != 0` ⇒ log, truncate; `< 16` bytes ⇒ stop.
9. **RTT adoption** from words 1–2 (values from the peer's receiver):
   - Before the sender has any RTT state (`!IsFirstRTTReceived`): adopt them
     directly (`SRTT = rtt, RTTVar = rttvar`), but only when **both** differ from
     their initial values (exact gate: `rtt != 100_000 && rttvar != 50_000`; if
     *either* still equals its initial value the ACK is treated as "peer has no
     measurement yet" and skipped).
   - After that, pure-sender case (no data received on this socket, i.e. normal
     live sender): keep adopting the peer's values as-is each full ACK.
   - Bidirectional case: 1.4.4 intends double-smoothing but the code computes
     `avg_iir<4>(RTTVar, |SRTT−SRTT|)`, `avg_iir<8>(SRTT, SRTT)` — a known 1.4.4
     bug that effectively decays RTTVar toward 0 and never updates SRTT from the
     ACK. Do not reproduce; for a live implementation adopting the peer's values
     as-is is correct and interoperable.
10. If CIF ≥ 24 bytes: smooth rates
    `Bandwidth = avg_iir<8>(Bandwidth, word5)`,
    `DeliveryRate = avg_iir<8>(DeliveryRate, word4)`,
    `ByteDeliveryRate = avg_iir<8>(ByteDeliveryRate, word6 or word4*payload_size)`
    — statistics only in live mode.
11. Notify congestion control (`TEV_ACK`) — LiveCC recomputes the pacing
    period; in auto mode (`MAXBW = 0`, `INPUTBW = 0`) the ceiling is first
    refreshed to `withOverhead(max(MININPUTBW, measured input rate))` (§3.3.2).

**In-flight limit recap:** a *new* packet may be emitted only while
`number_in_flight < min(FlowWindowSize, CongestionWindow)` where
`number_in_flight = seqoff(SndLastAck, SndCurrSeqNo) + 1`. `FlowWindowSize` is the
peer's latest advertised available buffer (or decremented by light ACKs between
full ACKs). Retransmissions are exempt.

---

## 7. Loss: detection, NAK, retransmission

### 7.1 Receiver: loss detection on data arrival (`processData`)

For each arriving data packet with sequence `seq` (after dispatch/dedup):

- `offset = seqoff(RcvLastSkipAck, seq)`; if `offset < 0` the packet is **belated**
  (already skipped/delivered region) — count in stats, drop. If
  `offset >= available buffer space` — no room: drop the packet; special case:
  TSBPD+TLPKTDROP on and the buffer is *empty* ⇒ unrecoverable sequence
  discrepancy ⇒ send SHUTDOWN and break the connection.
- Insert into the receive buffer at `offset`. A slot already occupied ⇒ duplicate,
  drop silently.
- **Gap check**: if `seqcmp(seq, incseq(RcvCurrSeqNo)) > 0`:
  the range `[incseq(RcvCurrSeqNo) .. decseq(seq)]` is newly missing ⇒
  - insert it into the **receiver loss list**, and
  - **immediately send a NAK** containing exactly that fresh range
    (`sendLossReport`; encoding per `packets.md` §5.4)
  - …unless reorder tolerance is active: with `SRTO_LOSSMAXTTL > 0` the fresh range
    instead enters a "fresh loss" staging list with a TTL of that many packets, and
    the NAK for it is sent only after TTL further packets arrive without it being
    filled. **Default `SRTO_LOSSMAXTTL = 0` ⇒ immediate NAK.** (Also on by default:
    the tolerance can grow dynamically only up to `SRTO_LOSSMAXTTL`, so with the
    default 0 it never activates. Implement immediate NAK only.)
  - and wake the TSBPD thread (a new later packet may set the skip deadline).
- If `seqcmp(seq, RcvCurrSeqNo) > 0`: `RcvCurrSeqNo = seq`.
  Else (filling a hole or belated-in-buffer): **remove `seq` from the loss list**
  (`unlose`).

### 7.2 Entries leave the receiver loss list when

1. the missing packet arrives (retransmitted or reordered) — `unlose(seq)`;
2. a **DROPREQ** covering them arrives (§8.3);
3. the TSBPD thread **skips** past them at their deadline (§8.2) —
   `dropFromLossLists(from, to)`.

(The loss list is also what pins the ACK value — §4.2 — so removal immediately
lets the ACK advance.)

### 7.3 Receiver: periodic NAK reports (`checkNAKTimer`)

Enabled by `SRTO_NAKREPORT` = true (default in live mode; capability negotiated in
the handshake). Every time the timer fires (checked at the ≤10 ms cadence):

- if the loss list is non-empty and `now > NextNAKTime`: send a NAK containing the
  **entire current loss list** (compressed ranges, ascending; truncated to
  `max_payload/4` 32-bit words — the remainder goes in later reports), then
  reschedule.
- Period recomputed after each send (and rolled forward when idle):

  ```
  NAKInterval = (SRTT + 4·RTTVar) / 2  µs      // LiveCC divides base by NakReportAccel = 2
  floor: 20 ms                                  // LiveCC m_iMinNakInterval_us = 20_000
  ```

  Before the first report the interval is the post-handshake initial value 300 ms
  (UDT legacy `MinNakInterval` — LiveCC installs the 20 ms floor at setup but the
  *current* interval remains 300 ms until first recomputation).
  Draft states the same `(RTT + 4·RTTVar)/2, min 20 ms` formula.

Rationale (draft §4.8.2): periodic re-requests repair lost NAKs at the cost of
occasional duplicate retransmissions.

### 7.4 Sender: processing a NAK (`processCtrlLossReport`)

Parse CIF items (single seq, or `lo|0x8000_0000` followed by `hi`). For each item:

| Condition | Action |
|---|---|
| range with `seqcmp(lo, hi) > 0` | attack/bug ⇒ **break connection** |
| any seq (or `hi`) newer than `SndCurrSeqNo` | attack/bug ⇒ **break connection** |
| `lo` ≥ `SndLastAck` | insert `[lo, hi]` into sender loss list |
| `lo` < `SndLastAck` ≤ `hi` | insert `[SndLastAck, hi]` (clip stale part) |
| whole **range** older than `SndLastAck` | reply **DROPREQ** msgno=0, range `[lo, hi]` (tells the receiver to stop NAKing packets the sender already dropped/released) |
| **single** seq older than `SndLastAck` | ignore silently |

Then reschedule the socket for immediate sending (retransmissions preempt new
data, §3.2). Duplicate insertions are merged by the loss-list container; NAK for a
packet already in the list is harmless.

### 7.5 Sender: retransmission (`packLostData`)

Loop: pop the **lowest** sequence from the sender loss list; for each:

1. `offset = seqoff(SndLastDataAck, seq)`; `offset < 0` (packet no longer tracked —
   normally prevented by §7.4 clipping) ⇒ send **DROPREQ** msgno=0, range
   `[seq, decseq(SndLastDataAck)]`, continue with next loss entry.
2. **Rexmit throttle** (`SRTO_RETRANSMITALGO = 1`, the 1.4.4 default, active only
   when the peer supports NAK reports): skip this sequence (leave it out of this
   round; a later NAK/periodic report will bring it back) if it was last
   retransmitted within the last `SRTT − 4·RTTVar` µs
   (`tsLastRexmit >= now − (SRTT − 4·RTTVar)`). Note the **minus**: with the
   initial 100/50 ms values the window is negative ⇒ throttle inactive until
   RTTVar converges. `SRTO_RETRANSMITALGO = 0` disables the throttle.
3. Read the packet from the send buffer at `offset`:
   - Buffer says the message was TTL-dropped (`readData` returns −1 with its
     message number and length `msglen`): send **DROPREQ**, Type-specific Info =
     message number, CIF range `[seq, incseq(seq, msglen−1)]`; remove up to that
     range end from the loss list; `SndCurrSeqNo = max(SndCurrSeqNo, range_end)`;
     continue. (In live mode with default msgttl = −1 this path is idle.)
   - Zero-length slot: continue.
4. Send it: original sequence number, original message number/flags, **original
   timestamp**, `R = 1` (`PACKET_SND_REXMIT` bit; set because the rexmit-flag
   capability is always negotiated with 1.4.4). Record per-packet
   `RexmitTime = now`. Count in retransmit stats.

If the loss list is empty, `packData` proceeds to new data (§3.2).

### 7.6 Blind retransmission (FASTREXMIT) — dormant with 1.4.4 peers

`checkRexmitTimer`: if no ACK progressed for
`ReXmitCount · (SRTT + 4·RTTVar + 2·10ms) + 10ms` µs and there is unacknowledged
data, LiveCC's FASTREXMIT would re-insert `[SndLastAck .. SndCurrSeqNo]` into the
loss list — **but only when the peer did NOT negotiate NAK reports**. libsrt 1.4.4
always negotiates NAK reports in live mode, so against the interop target this
never fires; implementing it is optional. `ReXmitCount` increments each timer
expiry and resets to 1 on any ACK progress.

---

## 8. Too-late packet drop (TLPKTDROP)

Enabled by `SRTO_TLPKTDROP` = true — the default in live mode, negotiated both
directions in the handshake (each side tells the peer whether it will drop).
`m_bPeerTLPktDrop` on the sender = "receiver-side peer expects drops".

### 8.1 Sender side (`checkNeedDrop` — runs on every application submit)

```
threshold_ms = max(PeerTsbPdDelay_ms + SRTO_SNDDROPDELAY, 1000) + 20
               // 1000 = SRT_TLPKTDROP_MINTHRESHOLD_MS ("keep at least 1 s")
               // 20   = 2 * COMM_SYN_INTERVAL (sender+receiver reaction time)
```

- `SRTO_SNDDROPDELAY` default **0**; value **−1 disables** sender-side dropping
  entirely (threshold_ms = 0). `PeerTsbPdDelay_ms` = the latency this sender must
  respect for the peer (negotiated at handshake).
  So by default, with latency ≤ 1 s: threshold = **1020 ms**; with latency > 1 s:
  `latency + 20 ms`. (The draft describes "≈ latency + min(1s, latency/4)" as a
  recommendation — 1.25×latency; **libsrt 1.4.4 actually uses the max() formula
  above. Follow libsrt.**)
- Trigger: if the send buffer **timespan** (newest origin time − oldest origin
  time) exceeds `threshold_ms`, drop from the buffer front every packet whose
  origin time `< now − threshold_ms`. Then, with `dpkts` dropped:
  - "fake ACK" them to self: `SndLastAck = SndLastDataAck = incseq(SndLastDataAck, dpkts)`;
  - purge the sender loss list up to `decseq(SndLastDataAck)`;
  - if unsent packets were dropped, `SndCurrSeqNo = max(SndCurrSeqNo, decseq(SndLastDataAck))`;
  - count in `sndDrop` stats; flag congestion.
- **libsrt 1.4.4 does NOT send a DROPREQ at drop time.** (Newer libsrt versions
  do.) The receiver learns of the hole either by skipping at its own TSBPD
  deadline (§8.2), or by NAKing the dropped range and getting DROPREQ back
  (§7.4/§7.5). For 1.4.4-faithful behavior: don't send DROPREQ here; sending one
  (msgno 0, dropped range) is nevertheless harmless and matches later versions.

### 8.2 Receiver side: skipping at the TSBPD deadline (tsbpd thread)

The receiver never blocks forever on a hole. The delivery loop (§9.5) computes,
for the **first available packet** in the buffer (search spans both the ACKed
region and packets received beyond a hole):

- if that packet's delivery time (§9.1) has arrived AND there are missing packets
  before it (`skiptoseqno` = its sequence): **drop the hole**:
  `[RcvLastSkipAck .. decseq(skiptoseqno)]` — remove the range from the loss list
  and fresh-loss list (no more NAKs for it), advance the buffer base:
  `RcvLastSkipAck = skiptoseqno`, count `rcvDrop` stats.
  The next ACK then automatically acknowledges past the hole — the draft calls
  this the "fake ACK"; in libsrt it is implicit in the advanced ACK position. The
  sender never learns the packets were skipped rather than delivered.
- packets whose time has not come are simply waited on (sleep until delivery time,
  woken early by new ACKs / DROPREQ / loss signal).

### 8.3 Receiver: processing DROPREQ (`processCtrlDropReq`)

DROPREQ (type `0x0007`, Type-specific Info = message number, CIF = `{first, last}`
inclusive — `packets.md` §5.8):

1. Mask the message number: `msgno = word1 & 0x03FF_FFFF`. If ≠ 0, drop that
   message from the receive buffer (live mode: at most one packet). 0 ⇒ skip this
   step (drop purely by range).
2. Remove `[first, last]` from the receiver loss list and fresh-loss list ⇒ no
   further NAKs for the range, ACK can advance.
3. If the range covers the next expected packet
   (`seqcmp(first, incseq(RcvCurrSeqNo)) <= 0 && seqcmp(last, RcvCurrSeqNo) > 0`):
   `RcvCurrSeqNo = last` (skip ahead).
4. Wake the TSBPD thread.
5. Never reply. (A lost DROPREQ is repaired by the NAK→DROPREQ cycle repeating.)

---

## 9. TSBPD — timestamp-based packet delivery (receiver)

### 9.1 Delivery time formula

```
PktTsbpdTime = TsbpdTimeBase [+ wrap carryover] + PKT_TIMESTAMP_us
               + TsbpdDelay_us + Drift_us
```

- `PKT_TIMESTAMP` — data packet header word 2 (µs, sender clock, mod 2^32).
- `TsbpdDelay` — the negotiated latency for this direction:
  `max(our SRTO_RCVLATENCY, peer's SRTO_PEERLATENCY proposal)`, resolved during
  the handshake (default 120 ms each ⇒ 120 ms).
- `Drift` — from the drift tracer (§9.4), 0 initially / if not implemented.
- The application receives the packet at `PktTsbpdTime` (in-order, §9.5).

### 9.2 Time base (anchor) establishment

Set once, when the SRT handshake extension arrives (before any data):

```
TsbpdTimeBase = now_local − HS_packet_timestamp
```

- **Listener** (HSREQ responder): from the caller's CONCLUSION handshake packet
  carrying the HSREQ extension: `now` at its arrival minus that packet's header
  timestamp.
- **Caller** (initiator): from the listener's CONCLUSION response carrying HSRSP,
  same formula.

Since the peer stamps every packet with `now_peer − peer_start_time`, the base
approximates `peer_start_time` mapped to local clock **plus the one-way trip time
of the handshake packet** (~RTT₀/2). That offset is inherent and constant; total
end-to-end latency ≈ RTT₀/2 + TsbpdDelay (draft §4.5).

### 9.3 32-bit timestamp wraparound — **MANDATORY**

`MAX_TIMESTAMP = 0xFFFF_FFFF` µs; the timestamp wraps every 2^32 µs ≈ **1 h 11 m
35 s**. The sender does nothing special (natural mod-2^32). The receiver
(`CTsbpdTime`, `TSBPD_WRAP_PERIOD = 30_000_000` µs = 30 s):

State: `TsbpdWrapCheck` flag (initially false).

- On every arriving data packet timestamp `ts` (call `updateTsbPdTimeBase(ts)`):
  - if `!TsbpdWrapCheck` and `ts > MAX_TIMESTAMP − 30s`: enter the wrap period
    (`TsbpdWrapCheck = true`).
  - if `TsbpdWrapCheck` and `30s <= ts <= 60s` (a small timestamp reappeared and
    settled): **commit the wrap**: `TsbpdTimeBase += 2^32 µs`
    (`MAX_TIMESTAMP + 1`), `TsbpdWrapCheck = false`.
- While `TsbpdWrapCheck` is set, delivery-time computation uses a per-packet
  carryover: for a timestamp `ts <= 60s` (i.e. an already-wrapped young packet
  mixed with pre-wrap stragglers), use
  `effective base = TsbpdTimeBase + 2^32 µs`; for large (pre-wrap) timestamps use
  the base unchanged. Exact rule: `carryover = (TsbpdWrapCheck && ts <= 2*30s) ? 2^32 : 0` µs.
- Store/handle the raw timestamp strictly as `u32`; do all math in 64-bit.

### 9.4 Drift tracing (OPTIONAL for a first implementation)

libsrt 1.4.4 (`SRTO_DRIFTTRACER` default on) samples on **every ACKACK** (§5.2):

```
sample_i  = now − (TsbpdTimeBase [+ wrap carryover] + ACKACK_timestamp)
            − (rtt_sample − first_rtt) / 2
```

(the RTT term compensates path-delay changes; `first_rtt` = the first ACKACK RTT
sample of the connection, used as an RTT₀ approximation).
After every `TSBPD_DRIFT_MAX_SAMPLES = 1000` samples, compute the plain average;
then:

- if `|avg| > TSBPD_DRIFT_MAX_VALUE = 5000` µs: shift the base:
  `TsbpdTimeBase += clamp(avg, ±5000)` and keep `Drift = avg − shift`;
- else `Drift = avg` (used directly in the §9.1 formula).

A first implementation may skip drift tracing entirely (`Drift = 0`); sender/
receiver clock drift only matters on multi-hour streams (µs/minute scale). The
wrap handling in §9.3 is NOT optional.

### 9.5 Delivery loop (what the tsbpd thread does)

Repeat:

1. Find the first packet in the receive buffer (scanning from the base
   `RcvLastSkipAck`; a packet is *deliverable* to the app only once it lies below
   the ACK position — packets beyond a hole are only used for deadline/skip
   decisions).
2. If there is a ready packet (its `PktTsbpdTime <= now`) with no hole before it:
   hand it to the application (in sequence order). Undecryptable packets
   (`KK != 0`, no crypto context) are discarded here at the latest — never
   delivered (see `packets.md` §3.2).
3. If the first *available* packet is ready but preceded by a hole: TLPKTDROP skip
   (§8.2), then loop.
4. If the next packet exists but its time is in the future: sleep until
   `PktTsbpdTime` (interruptible by: new ACK advancing the deliverable region, a
   detected loss, DROPREQ, close).
5. If the buffer has nothing: sleep until woken by an ACK.

Timestamps of *control* packets never drive delivery; only data-packet timestamps
do (plus ACKACK timestamps for drift).

---

## 10. Timers and liveness — summary

All periods in the table are libsrt 1.4.4 values. Timer evaluation cadence:
on every received packet and at least every 10 ms per socket — confirmed
end-to-end: `CChannel::recvfrom` uses a `select()` timeout of exactly 10 000 µs
(`channel.cpp`), so even in total silence the rcv-queue worker loop wakes every
10 ms and runs `checkTimers()` for every socket not checked within the last
`COMM_SYN_INTERVAL` (10 ms).

| Timer | Period / rule | Action |
|---|---|---|
| Full ACK | 10 ms (`COMM_SYN_INTERVAL_US = 10_000` µs) | receiver sends full ACK (§4) |
| Light ACK | every 64 received packets between timer ACKs (scaling 64·n) | receiver sends light ACK |
| ACK repeat (un-ACKACKed) | not more often than `SRTT + 4·RTTVar` µs | re-announce same ACK position |
| ACKACK throttle | ≥ 10 ms since last, or repeated ACK number | sender answers non-lite ACK |
| Periodic NAK | `(SRTT + 4·RTTVar)/2` µs, floor 20 ms (initially 300 ms until first recomputation) | receiver re-sends loss list |
| Sender rexmit throttle | per packet: once per `SRTT − 4·RTTVar` µs | skip too-recent rexmits (§7.5) |
| FASTREXMIT (dormant vs 1.4.4) | `ReXmitCount·(SRTT + 4·RTTVar + 20ms) + 10ms` since last ACK progress | blind re-insert of in-flight range — only if peer lacks NAK report |
| Keepalive | 1 s (`COMM_KEEPALIVE_PERIOD_US = 1_000_000` µs) since **anything was sent** | send KEEPALIVE (20-byte packet, §`packets.md` 5.2) |
| EXP (liveness probe) | `EXPCount·(SRTT + 4·RTTVar) + 10ms` µs since last packet **received**, min `EXPCount·300ms`; then `EXPCount++` | none per se (counter escalation) |
| **Peer idle timeout** | `EXPCount > 16` (`COMM_RESPONSE_MAX_EXP`) **AND** ≥ 5 s (`SRTO_PEERIDLETIMEO` default `COMM_RESPONSE_TIMEOUT_MS = 5000`) with nothing received | **connection broken** — close, notify app (`SRT_ECONNLOST`) |
| Handshake retransmit (pre-connection; handshake doc) | 250 ms without response | caller re-sends HS request; overall `SRTO_CONNTIMEO` default 3 s |

Liveness bookkeeping: **any** packet received from the peer (data or control,
including KEEPALIVE) resets `EXPCount = 1` and refreshes `LastRspTime`. Received
KEEPALIVE triggers no reply.

With default values the effective break time is dominated by the 5 s idle
timeout (16 expirations pass long before 5 s when RTT is at its initial 100 ms).

---

## 11. Shutdown and teardown

- **Sending**: on application `close()` of a connected socket, libsrt sends
  **one** SHUTDOWN control packet (type `0x0005`, no CIF → 20 bytes on the wire
  with the zero pad) — best effort, **not retransmitted**, no reply expected. It
  is skipped if the connection is already known broken or the peer already sent
  its own SHUTDOWN. It is also sent when the stack must unilaterally kill an
  established connection (fatal inconsistency, e.g. receive-buffer sequence
  discrepancy, §7.1), and by a caller aborting a rejected connection attempt.
- **Receiving** (`processCtrlShutdown`): immediately mark the connection
  shutdown/closing/**broken** (libsrt sets `BrokenCounter = 60`), release
  blocked API calls, signal epoll error/readiness. No response is sent. Data
  already in the receive buffer may still be read by the application; nothing new
  is accepted. `BrokenCounter` semantics (confirmed in `api.cpp`): the GC thread
  ticks every **1 s** (`garbageCollect`: `wait_for(1 s)`), and `checkBrokenSockets`
  decrements the counter once per tick *only while unread data remains in the
  receive buffer* — i.e. a broken socket with pending data lingers up to ~60 s for
  the app to drain it; with no pending data it is closed at the next GC tick.
  (Other break paths use different values: 30 on peer-idle expiry, 0 on
  attack/rogue breaks — the counter only matters app-locally.)
- If the single SHUTDOWN datagram is lost, the peer discovers the death via the
  5-second peer-idle timeout (§10).
- Live mode sets `SO_LINGER` off (`l_onoff=0`) — `close()` does not wait to flush
  the send buffer.
- After close, a socket lingers internally only for GC; packets arriving for a
  closed/unknown Socket ID are discarded (see dispatch rules, `packets.md` §7).

---

## 12. Other control packets in live mode

| Packet | 1.4.4 sender behavior | Required receiver behavior (this implementation) |
|---|---|---|
| Congestion Warning `0x0004` | **never sent** | On receive libsrt multiplies the inter-packet send interval by 1.125 (`interval = interval*1125/1000`). Mimic that (harmless; pacing is input-driven in live) or ignore. Never send. |
| PEERERROR `0x0008` | sent only by a *file-mode* receiver on storage errors | Live: **ignore** (optionally log). libsrt only flags "peer unhealthy" to unblock file APIs. Never send. |
| KEEPALIVE `0x0001` | 1 s idle rule (§10) | refresh liveness only; ignore CIF; never reply |
| User-defined `0x7FFF` (`UMSG_EXT`) | KM refresh (encrypted peers), HSv4 negotiation | unencrypted HSv5 implementation: **ignore** — that is what default-config libsrt 1.4.4 does with a failed in-stream KMREQ (enforced encryption suppresses the KMRSP reply); only the non-default permissive mode answers with KMRSP = `SRT_KM_S_NOSECRET` (see `packets.md` §5.10) |
| Unknown control type | n/a | **silently ignore** (libsrt `processCtrl` default case does nothing). Still counts as peer activity for liveness. |
| HANDSHAKE `0x0000` on established conn. | peer repeats CONCLUSION when the final HS response was lost | re-send the CONCLUSION response (handshake doc); do not disturb transmission |

General rule: never break the connection on an unrecognized control packet —
only the explicitly listed attack/bug conditions (§6 step 5, §7.4) do that.

---

## 13. Quick reference — constants introduced in this document

| Constant | Value | Where |
|---|---|---|
| `COMM_SYN_INTERVAL_US` | 10 000 µs | ACK period, ACKACK throttle, timer math |
| `SELF_CLOCK_INTERVAL` | 64 packets | light ACK trigger |
| `SEND_LITE_ACK` | 4 bytes | light ACK CIF size |
| `ACK_WND_SIZE` | 1024 entries | ACK→ACKACK RTT history |
| `INITIAL_RTT` / `INITIAL_RTTVAR` | 100 000 / 50 000 µs | pre-measurement values |
| RTT smoothing | `RTTVar = (3·RTTVar + |rtt−SRTT|)/4`, then `SRTT = (7·SRTT + rtt)/8` | §5.2 |
| First RTT sample | `SRTT = rtt`, `RTTVar = rtt/2` | §5.2 |
| NAK period (live) | `(SRTT + 4·RTTVar)/2` µs, floor 20 000 µs | §7.3 |
| Rexmit throttle window | `SRTT − 4·RTTVar` µs | §7.5 |
| Sender TLPKTDROP threshold | `max(peer_latency_ms + SRTO_SNDDROPDELAY, 1000) + 20` ms | §8.1 |
| `SRTO_SNDDROPDELAY` default | 0 (−1 disables sender drop) | §8.1 |
| ACK avail-buffer floor | 2 packets | §4.3 |
| Receive-rate window / probe window | 16 / 64 samples, median-filter (÷8, ×8) | §4.4 |
| Probe pair | after packet with `seq & 0xF == 0` | §3.3.4 |
| LiveCC pacing | `1e6·(avg_payload+44)/max_bw` µs, truncated to whole µs | §3.3.1 |
| `SRTO_MAXBW` default | −1 → `BW_INFINITE` = 125 000 000 B/s | §3.3.2 |
| `SRTO_OHEADBW` | default 25 %, range 5..=100 | §3.3.2 |
| `SRTO_INPUTBW` / `SRTO_MININPUTBW` defaults | 0 / 0 | §3.3.2 |
| Input-rate sampler | 500 ms fast-start / 1 s running windows, >2000-pkt early close, init `BW_INFINITE` | §3.3.3 |
| Payload sizes | max 1456; live default 1316 | §3.1 |
| Keepalive | 1 s since last send | §10 |
| Peer idle timeout | `EXPCount > 16` AND > 5000 ms silence | §10 |
| `MAX_TIMESTAMP` | `0xFFFF_FFFF` µs (≈ 71 min 35 s) | §9.3 |
| `TSBPD_WRAP_PERIOD` | 30 s | §9.3 |
| Drift tracer | 1000 samples per batch, ±5000 µs max drift before base shift | §9.4 |
| Latency default | 120 ms (`SRTO_RCVLATENCY`/`SRTO_PEERLATENCY`), negotiated = max of proposals | §9.1 |
| `SRTO_FC` default | 25600 packets | flow window |
| Snd/Rcv buffer default | 8192 packets | §2 |
| Handshake retransmit | 250 ms | §10 |
