# SRT Packet Structure

Interop target: **libsrt 1.4.4** (`srt-live-transmit`), HSv5, caller–listener, LIVE mode only.

Sources:

- Primary: IETF `draft-sharabayko-srt-01` (2021-09-07; the newest revision — the draft
  expired 2022-03-11 and was **never published as an RFC**), Section 3 and Appendix A.
- Secondary: libsrt v1.4.4 sources (`srtcore/packet.{h,cpp}`, `core.{h,cpp}`,
  `common.h`, `congctl.cpp`, `queue.cpp`) and `docs/features/handshake.md`.

Where the draft and libsrt 1.4.4 disagree, **libsrt 1.4.4 behavior is normative for this
implementation** and the difference is called out explicitly.

Out of scope here: handshake CIF internals (see `handshake.md` sibling doc), encryption/KM
payloads, packet filter, bonding. They are mentioned only where a receiver must
reject/ignore them.

---

## 1. Conventions

- Every SRT packet is the complete payload of one UDP datagram. One UDP datagram = one
  SRT packet; SRT packets are never split across datagrams or concatenated.
- **Byte order: network byte order (big-endian), applied per 32-bit word.** libsrt
  serializes the 16-byte header as four 32-bit words with `htonl()`. For **control**
  packets the Control Information Field (CIF) is *also* converted as a sequence of 32-bit
  big-endian words (`CPacket::toNL()` swaps every 4-byte word of the CIF). The **data
  packet payload is never byte-swapped** — it is opaque bytes.
  (Exception inside the handshake CIF: the StreamID extension content has a special
  little-endian-block encoding — covered in the handshake doc.)
- Bit numbering in the layout tables below follows RFC diagrams: **bit 0 = most
  significant bit** of the 32-bit word.
- "Sequence number" arithmetic is modulo 2^31 (31-bit numbers, values
  `0x00000000..0x7FFFFFFF`); comparison is circular (UDT `CSeqNo` style). Details in the
  data-transmission sibling doc.

---

## 2. Common 16-byte packet header

Every SRT packet (data and control) starts with this 16-byte header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F|         (meaning depends on F)                              |  word 0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          (meaning depends on F)                               |  word 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |  word 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Destination Socket ID                     |  word 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Byte offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | Word 0 | Bit 0 = **F** (Packet Type Flag): `0` = data, `1` = control. Remaining 31 bits depend on F. Extraction: `F = word0 & 0x8000_0000`. |
| 4 | 4 | Word 1 | Data: message-number word. Control: Type-specific Information. |
| 8 | 4 | Timestamp | 32-bit unsigned, microseconds since the sender's socket start time. Set on **every** packet libsrt sends, data and control alike. See §6. |
| 12 | 4 | Destination Socket ID | SRT socket ID of the peer socket this packet is addressed to; `0` for connection-request handshakes. See §7. |

libsrt field-index names (host-order array of 4 × `uint32_t`): `SRT_PH_SEQNO`=0,
`SRT_PH_MSGNO`=1, `SRT_PH_TIMESTAMP`=2, `SRT_PH_ID`=3.

---

## 3. Data packets (F = 0)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|                  Packet Sequence Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|P P|O|K K|R|                Message Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Destination Socket ID                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload (opaque bytes) ...            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.1 Word 0 — Packet Sequence Number

| Bits | Field | Extraction |
|---|---|---|
| 0 | F = 0 | `word0 & 0x8000_0000 == 0` |
| 1–31 | Packet Sequence Number (31-bit) | `word0 & 0x7FFF_FFFF` |

- Initial value (ISN) is chosen randomly at connection setup and exchanged in the
  handshake CIF. Increments by 1 per data packet, modulo 2^31.
- A retransmitted packet reuses its **original** sequence number.

### 3.2 Word 1 — Message number word

| Bits | Field | Mask (host order) | Meaning |
|---|---|---|---|
| 0–1 | **PP** Packet Position | `0xC000_0000` (`>>30`) | `10b`=first packet of a message, `00b`=middle, `01b`=last, `11b`=solo (single-packet message). libsrt enum: `PB_FIRST=2, PB_SUBSEQUENT=0, PB_LAST=1, PB_SOLO=3`. |
| 2 | **O** Order flag | `0x2000_0000` (`>>29`) | `1` = message must be delivered in order. |
| 3–4 | **KK** Key-based Encryption flag | `0x1800_0000` (`>>27`) | `00b`=not encrypted, `01b`=even key, `10b`=odd key. `11b` is invalid in data packets (per draft it is "only used in control packets"). |
| 5 | **R** Retransmitted flag | `0x0400_0000` (`>>26`) | `0` on first transmission, `1` on any retransmission. |
| 6–31 | **Message Number** (26-bit) | `0x03FF_FFFF` | Sequential message counter. |

Message number rules (libsrt 1.4.4, `buffer.cpp`):

- Starts at **1** for the first message sent on a connection.
- Increments by 1 per message; wraps within the 26-bit space back to 1. In the live
  path (`CSndBuffer::addBuffer`, `RollNumber` increment) values run
  `1..0x03FF_FFFF` inclusive, then the next increment wraps to 1; message number
  `0` is never generated — `0` means "unknown" in DROPREQ, see §5.8.
- All packets of one message carry the same message number.

**R-flag / 26-vs-27-bit caveat:** the R bit exists only when both peers negotiated the
"rexmit flag" capability (`SRT_OPT_REXMITFLG`, part of the handshake extension flags —
always set by libsrt ≥ 1.2.0, so always set for our 1.4.4 target). Against a peer without
that capability, bit 5 would instead be the MSB of a **27-bit** message number
(mask `0x07FF_FFFF`). For this implementation: always use the 26-bit form; the flag is
always negotiated with libsrt 1.4.4.

**LIVE mode profile** (what libsrt 1.4.4 actually puts on the wire in live mode, and what
this implementation must send):

- Every data packet is a solo message: `PP = 11b`.
- `O = 0` (default `SRT_MSGCTRL.inorder = false`; ordering in live mode is done by
  TSBPD from timestamps, the O flag is ignored by the receiver).
- `KK = 00b` (unencrypted). **If a receiver without a crypto context receives a data
  packet with `KK != 0`, it cannot decrypt it and MUST drop the packet** (libsrt counts
  it in `rcvUndecrypt` stats and discards). A connection where the peer demands
  encryption is normally rejected during the handshake (see handshake doc), so this only
  happens on misbehaving peers.
- Message number increments by 1 for **every packet**.

### 3.3 Payload

- Length = UDP datagram length − 16. No length field of its own.
- Maximum payload: `SRT_MAX_PAYLOAD_SIZE = 1456` bytes (1500 MTU − 28 UDP/IP hdr − 16 SRT
  hdr). Live-mode default configured payload is `SRT_LIVE_DEF_PLSIZE = 1316` (= 7×188,
  MPEG-TS friendly); absolute live max `SRT_LIVE_MAX_PLSIZE = 1456`.

---

## 4. Control packets (F = 1)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|        Control Type         |           Subtype             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Type-specific Information                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Destination Socket ID                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Control Information Field (CIF), variable ...        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Word 0 extraction: `type = (word0 >> 16) & 0x7FFF`, `subtype = word0 & 0xFFFF`.

- **Subtype** is `0x0` for all standard types. It is meaningful only for
  Control Type `0x7FFF` (user-defined / extended messages, §5.10). libsrt does not
  validate subtype on standard types — ignore it on receive, send `0`.
- **Type-specific Information** ("additional info" in UDT): use per type, see table.
  Set to `0` when unused.
- **CIF**: sequence of 32-bit big-endian words; length = UDP datagram length − 16.

### 4.1 Control packet types

| Packet type | Control Type (hex, 15-bit) | Subtype | Type-specific Information (word 1) | CIF |
|---|---|---|---|---|
| HANDSHAKE | `0x0000` | 0 | unused (0) | Handshake structure, ≥ 48 bytes (§5.1, sibling doc) |
| KEEPALIVE | `0x0001` | 0 | unused (0) | none (libsrt sends 4 zero bytes, §4.2) |
| ACK | `0x0002` | 0 | ACK number (0 for Light ACK) | 1, 4, 6 or 7 words (§5.3) |
| NAK (Loss Report) | `0x0003` | 0 | unused (0) | loss list, ≥ 1 word (§5.4) |
| Congestion Warning | `0x0004` | 0 | unused (0) | none (§5.5) |
| SHUTDOWN | `0x0005` | 0 | unused (0) | none (libsrt sends 4 zero bytes, §5.6) |
| ACKACK | `0x0006` | 0 | ACK number being acknowledged | none (libsrt sends 4 zero bytes, §5.7) |
| DROPREQ | `0x0007` | 0 | Message number (0 = unknown) | 2 words: first, last seq no (§5.8) |
| PEERERROR | `0x0008` | 0 | Error code | none (libsrt sends 4 zero bytes, §5.9) |
| User-defined | `0x7FFF` | extended type | per extended type | per extended type (§5.10) |

libsrt enum (`UDTMessageType`, `common.h`): `UMSG_HANDSHAKE=0, UMSG_KEEPALIVE=1,
UMSG_ACK=2, UMSG_LOSSREPORT=3, UMSG_CGWARNING=4, UMSG_SHUTDOWN=5, UMSG_ACKACK=6,
UMSG_DROPREQ=7, UMSG_PEERERROR=8, UMSG_EXT=0x7FFF`.

Receive rule: unknown control types are silently ignored (libsrt `processCtrl` `default:`
case does nothing). Any received packet (any type) refreshes the peer-liveness timer.

### 4.2 The 4-byte padding quirk (important for interop)

The draft says KEEPALIVE, SHUTDOWN, ACKACK (and implicitly Congestion Warning, Peer
Error) "do not contain CIF". **On the wire, libsrt always sends these packets with a
4-byte all-zero CIF** (a `writev` limitation workaround: `CPacket::pack()` attaches
`m_extra_pad`, a zero `int32_t`, to UMSG_KEEPALIVE, UMSG_SHUTDOWN, UMSG_ACKACK,
UMSG_CGWARNING, UMSG_PEERERROR, and to UMSG_EXT when it has no payload). So these packets
are **20 bytes**, not 16.

Implementation rules:

- On receive: accept CIF length 0 **or** 4 (or anything else) for these types and ignore
  the CIF bytes.
- On send: attach the 4 zero bytes to match libsrt exactly. (Exception: do NOT let this
  pad make an ACK 4 bytes long — a 4-byte ACK CIF *is* the Light ACK encoding, §5.3.4.)

---

## 5. Control Information Field per type

### 5.1 HANDSHAKE (`0x0000`)

Carries the handshake structure (Version, Encryption Field, Extension Field, ISN, MTU,
flow window, Handshake Type, SRT Socket ID, SYN Cookie, Peer IP, extension blocks…),
minimum 48 bytes. **The full CIF layout, extension blocks, and the state machine are
documented in the sibling handshake doc** — not here. Type-specific Information (word 1)
is unused (0). Destination Socket ID rules for handshakes: §7.

### 5.2 KEEPALIVE (`0x0001`)

- Type-specific Information: unused, 0. CIF: none (4 zero bytes on the wire, §4.2).
- Sent when **1 second** (`COMM_KEEPALIVE_PERIOD_US = 1_000_000` µs) has elapsed since
  the last packet (data or control) was *sent* on the socket. Checked in the timer loop.
- On receive: no action beyond refreshing liveness. (libsrt 1.4.4 parses an optional CIF
  value only for bonding groups — out of scope; ignore CIF.)

### 5.3 ACK (`0x0002`)

The receiver-side of the data stream produces ACKs; the data sender consumes them.

**Type-specific Information (word 1) = Acknowledgement Number ("ACK number", a.k.a. ACK
journal / sub-sequence number):**

- Independent counter, **not** related to packet sequence numbers.
- libsrt initializes it to 0 and increments *before* sending, so the first Full/Small ACK
  carries ACK number **1**. Increment: `ackno == 0x7FFF_FFFF ? 0 : ackno + 1`
  (`CAckNo::incack`, max `0x7FFF_FFFF`).
- Light ACKs carry ACK number **0** and do not advance the counter.
- The ACK number is echoed back in ACKACK (§5.7) and matched against a history window
  (`ACK_WND_SIZE = 1024` entries in libsrt) to compute RTT on the receiver side.

**Full ACK CIF — 7 × 32-bit words (28 bytes), in this exact order:**

| Word | Byte off. in CIF | Field | Units / semantics |
|---|---|---|---|
| 0 | 0 | Last Acknowledged Packet Sequence Number | **Sequence number of the last received-in-contiguity data packet, plus 1** — i.e. the first *not yet* acknowledged sequence number (past-the-end). If losses exist, this is the first loss; the ACK acknowledges everything strictly before it. |
| 1 | 4 | RTT | µs. Receiver's smoothed RTT estimate from ACK/ACKACK pairs. Initial value before any measurement: `INITIAL_RTT = 100_000` µs (100 ms). |
| 2 | 8 | RTT variance | µs. Initial `INITIAL_RTTVAR = 50_000` µs (50 ms). |
| 3 | 12 | Available Buffer Size | **packets** free in the receiver buffer. libsrt clamps to a minimum of **2** even when the buffer is full (deadlock-breaker). The data sender adopts this value as its flow window. |
| 4 | 16 | Packets Receiving Rate | packets/second (0 if unknown). |
| 5 | 20 | Estimated Link Capacity | packets/second (0 if unknown). |
| 6 | 24 | Receiving Rate | **bytes**/second (0 if unknown). |

libsrt field-index constants: `ACKD_RCVLASTACK=0, ACKD_RTT=1, ACKD_RTTVAR=2,
ACKD_BUFFERLEFT=3, ACKD_RCVSPEED=4, ACKD_BANDWIDTH=5, ACKD_RCVRATE=6`; sizes
`ACKD_TOTAL_SIZE_SMALL=4` words (16 B), `ACKD_TOTAL_SIZE_UDTBASE=6` words (24 B),
`ACKD_TOTAL_SIZE_VER101=7` words (28 B). (An 8-word / 32-byte variant
`ACKD_TOTAL_SIZE_VER102_ONLY` exists solely for peers reporting SRT version exactly
1.0.2 — never occurs with a 1.4.4 peer; ignore any words beyond 7.)

#### 5.3.1 ACK variants and how they are distinguished

**Only by CIF length.** The header gives no indication.

| Variant | CIF length | Fields present | ACK number (word 1 of header) |
|---|---|---|---|
| **Light ("lite") ACK** | exactly **4 bytes** (`SEND_LITE_ACK`) | word 0 only (Last ACK seq +1) | `0` |
| **Small ACK** | **16 bytes** (4 words) | words 0–3 (…Available Buffer Size) | real ACK number (libsrt) — see divergence below |
| **Full ACK** | **24 or 28 bytes** (6 or 7 words) | words 0–5 or 0–6 | real ACK number |

Receive-side parsing rules (mirroring libsrt `processCtrlAck`):

1. `len == 4` → Light ACK: update last-ACK sequence and flow window
   (`flow_window -= seq_offset(last, new)`), nothing else. Do **not** send ACKACK.
2. Otherwise require `len >= 16`; log-and-ignore the extra bytes if `len % 4 != 0`;
   discard the whole ACK if fewer than 4 words.
3. Words 4–5 (rate, capacity) parsed only if `len > 16` (i.e. ≥ 24).
4. Word 6 (bytes/sec receiving rate) parsed only if `len > 24` (i.e. ≥ 28); when absent,
   libsrt approximates `bytes_ps = packets_ps * max_payload_size`.
5. Send ACKACK for every non-lite ACK, throttled: only if strictly more than 10 ms
   (`COMM_SYN_INTERVAL_US`) since the last ACKACK was sent **or** the ACK number equals
   the previously acked one (which signals a lost ACKACK).
6. Sanity check: if the acknowledged sequence is ahead of the highest sequence actually
   sent + 1, treat as attack/bug → **break the connection** (libsrt sets `m_bBroken`).
7. An ACK whose sequence is not newer than the last full ACK processed is a duplicate:
   flow window/last-ACK still updated if `>=` last ACK, but RTT/rate fields are skipped.

**Divergence (draft vs libsrt):** the draft says Light *and* Small ACK "set the
Type-specific Information field to 0". libsrt 1.4.4 sets it to 0 **only for Light ACK**;
Small ACKs get a real, incremented ACK number (they go through the same journal and are
answered with ACKACK). Follow libsrt.

#### 5.3.2 When each variant is sent (libsrt 1.4.4 cadence)

- **Full ACK: every 10 ms** (`m_tdACKInterval = COMM_SYN_INTERVAL_US = 10_000` µs timer),
  provided something new can be acknowledged.
- **Light ACK: every 64 packets** (`SELF_CLOCK_INTERVAL = 64`) received since the last
  timer-driven ACK, i.e. when `pkt_count >= 64 * light_ack_count` between ACK-timer
  ticks — a high-bitrate self-clocking supplement. The 64-packet counter scales
  (2nd light ACK after 128, etc.) and resets at every timer-driven ACK.
- **Small ACK:** sent by the timer path when the ACK timer fires but less than 10 ms has
  passed since the last full-ACK payload was built (`now - last_ack_time <=
  m_tdACKInterval`) — in practice a rare, jitter-driven case (or with a congctl that
  defines a shorter ACK period). Do not rely on ever *receiving* one, but parse it.
- No ACK is sent at all while there is nothing new to acknowledge **and** the previous
  ACK position has already been ACKACK-ed. If the ACK position is unchanged but not yet
  ACKACK-ed, the ACK is repeated no more often than `RTT + 4*RTTVar` µs.
- What sequence number goes into CIF word 0: first loss if the receiver loss list is
  non-empty, else (highest received seq + 1).

### 5.4 NAK / Loss Report (`0x0003`)

- Type-specific Information: unused (0).
- CIF = **loss list**: 1..N 32-bit words, two encodings (draft Appendix A):

```
Single lost packet:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|      lost packet sequence number             |   1 word, MSB = 0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Range of lost packets [lo..hi] (inclusive):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|      lo — first lost sequence number         |   MSB = 1  (word | 0x8000_0000)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|      hi — last lost sequence number          |   MSB = 0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Encoding rules (libsrt `addLossRecord` / `getLossArray`):

- `lo == hi` → encode as a single word. `lo != hi` (even a 2-packet range) → encode as a
  range pair. (The draft phrases it as "difference more than 1" but libsrt emits range
  pairs for any `hi > lo`; a decoder must accept a range pair whose span is any size ≥ 1,
  including degenerate `hi == lo`.)
- Items MUST be emitted **in ascending sequence order and non-overlapping**; libsrt's
  loss-list container produces them that way and its receiver-side merge logic assumes
  it. (The 1.4.4 *parser* would technically process out-of-order entries, but emit
  ascending — required for correct behavior of older/other stacks.)
- A NAK carries at most as many words as fit in one packet's payload
  (`max_payload_size / 4` words); libsrt truncates the list to that and re-sends the
  rest in later periodic NAKs.

Validation on receive — the data sender (libsrt `processCtrlLossReport`) checks each item;
violation ⇒ treated as attack/bug ⇒ **connection broken**:

- range with `lo > hi` (circular compare) → break;
- any sequence (single or `hi`) newer than the highest sequence sent so far → break;
- items entirely older than the last ACKed sequence are ignored (stale); if a range ends
  ≥ last-ACK it is clipped to start at last-ACK;
- a loss range that predates anything ever sent triggers a DROPREQ response with message
  number 0 (§5.8) instead of retransmission.

When NAKs are sent (receiver side, live mode):

- **Immediately** upon detecting a sequence gap in arriving data (NAK with the freshly
  detected range).
- **Periodically** while the loss list is non-empty ("NAK report", enabled by default in
  live mode): period = `(RTT + 4*RTTVAR) / 2` µs (LiveCC divides by
  `m_iNakReportAccel = 2`), lower bound **20 ms** (`m_iMinNakInterval_us = 20_000`).
  Before congctl setup the floor is 300 ms (UDT legacy default) — irrelevant in
  practice, since LiveCC installs the 20 ms floor at connection setup.

### 5.5 Congestion Warning (`0x0004`)

- Reserved/vestigial (UDT legacy). Type-specific Information 0; no CIF (4-byte pad rule
  §4.2 applies when sending).
- **libsrt 1.4.4 never sends it.** On receive it multiplies the inter-packet send
  interval by 1.125 (`interval = interval * 1125 / 1000`, i.e. +12.5%).
- This implementation: never send; on receive either ignore or mimic the 12.5% slowdown
  (mimicking libsrt is preferred; harmless in live mode where pacing is input-driven).

### 5.6 SHUTDOWN (`0x0005`)

- Type-specific Information: unused (0). No CIF (libsrt sends the 4-byte zero pad → 20-byte packet).
- Sent once (not retransmitted) when closing an established connection; libsrt skips
  sending it if the peer socket ID is not yet known.
- On receive: the connection is immediately considered closed/broken
  (`processCtrlShutdown`: sets shutdown/closing/broken); no reply is sent.

### 5.7 ACKACK (`0x0006`)

- **Type-specific Information = the ACK number** copied from the Full/Small ACK being
  acknowledged. No CIF (4-byte zero pad on the wire).
- Sent by the **data sender** in response to non-lite ACKs, subject to the 10 ms /
  duplicate-ACK-number throttle described in §5.3.1 step 5. Sent immediately upon ACK
  receipt (not timer-batched). Note the draft says ACKACK acknowledges "Full ACK" only;
  in libsrt 1.4.4 Small ACKs are also non-lite and get ACKACKs.
- On receive (the data receiver):
  - look up the ACK number in the stored ACK history (ACK number → (last acked seq,
    ACK send time), window of 1024): RTT sample = now − ACK send time;
  - update smoothed RTT/RTTVar: first sample: `SRTT = rtt, RTTVar = rtt/2`; then
    `RTTVar = avg_iir<4>(RTTVar, |rtt − SRTT|)`, `SRTT = avg_iir<8>(SRTT, rtt)`
    (`avg_iir<N>(old, s) = old + (s − old)/N`);
  - unknown ACK number: ignore (log only);
  - advance `last ACKACK-ed sequence` (used to decide whether ACKs must be repeated);
  - the ACKACK's **timestamp** header field is used as a TSBPD drift sample (see TSBPD doc).

### 5.8 DROPREQ — Message Drop Request (`0x0007`)

Sent by the **data sender** to tell the receiver to stop waiting for (and stop NAKing)
packets the sender can no longer retransmit.

- **Type-specific Information = Message Number** of the dropped message.
  - On receive, libsrt masks it through the message-number field mask: effective value =
    `word1 & 0x03FF_FFFF` (26-bit, given the rexmit-flag capability; `0x07FF_FFFF` for
    ancient peers). Upper bits may contain garbage flags — always mask.
  - `0` = message number unknown; the receiver then drops purely by the sequence range.
- **CIF = 2 × 32-bit words:**

| Word | Field |
|---|---|
| 0 | First Packet Sequence Number of the drop range |
| 1 | Last Packet Sequence Number of the drop range (**inclusive**) |

- When libsrt 1.4.4 sends it (all sender-side, all immediate, not periodic):
  1. Receiver NAKed packets that are no longer in the sender's buffer
     (already dropped by sender-side TLPKTDROP): range = the requested packets,
     message number from the buffer if recoverable, else the field is 0.
  2. Receiver NAKed a range that predates anything in the buffer entirely:
     message number 0, range = the NAKed range (defensive).
  - Note: ordinary sender-side too-late drop (TLPKTDROP) does **not** itself emit
    DROPREQ in 1.4.4 — the receiver's own too-late mechanism is expected to skip those
    packets; DROPREQ only appears once the receiver NAKs them.
- On receive (`processCtrlDropReq`):
  - drop the message with that number from the receive buffer (no-op if msgno = 0);
  - remove `[first..last]` from the receiver loss list (they will no longer be NAKed);
  - if the range covers the current receive position (`first <= rcv_curr_seq + 1` and
    `last > rcv_curr_seq`, circular), advance the current receive sequence to `last`;
  - wake the TSBPD thread so delivery can skip ahead.
  - No reply is sent; a lost DROPREQ is naturally repaired because continued NAKs
    provoke another DROPREQ.

### 5.9 PEERERROR (`0x0008`)

- **Type-specific Information = Error Code.** Only defined value: `4000` — file-system
  error during a file transfer (receiver failed writing to disk). No CIF (4-byte pad).
- Only used with File Transfer Congestion Control; **never sent in live mode.**
- This implementation: never send. On receive, libsrt marks "peer unhealthy" to unblock
  file-send calls — for a live-only implementation, safely **ignore** (log).

### 5.10 User-defined / extended (`0x7FFF`, `UMSG_EXT`)

Word 0 carries `type = 0x7FFF` and **Subtype = extended type**. Extended types defined by
SRT (all HSv4-era or KM refresh):

| Subtype | Name | Purpose |
|---|---|---|
| `0x0001` | `SRT_CMD_HSREQ` | HSv4 SRT capability negotiation (in-stream) |
| `0x0002` | `SRT_CMD_HSRSP` | HSv4 response |
| `0x0003` | `SRT_CMD_KMREQ` | Key material (initial in HSv4; **KM refresh in HSv5**) |
| `0x0004` | `SRT_CMD_KMRSP` | KM response |

For this implementation (HSv5-only, unencrypted):

- Never send any `0x7FFF` packet.
- `HSREQ`/`HSRSP` over `UMSG_EXT` never occur on an HSv5 connection (capability exchange
  happens inside the handshake CIF). If received: ignore.
- `KMREQ` over `UMSG_EXT` (in-stream KM refresh) can only originate from an *encrypted*
  peer. What an unencrypted libsrt 1.4.4 agent does (verified in `processSrtMsg` /
  `crypto.cpp processSrtMsg_KMREQ`) depends on `SRTO_ENFORCEDENCRYPTION`:
  - **Default (`ENFORCEDENCRYPTION=true`): it sends NO reply at all** — the failed
    KMREQ produces a one-word error result internally, the enforced-encryption check
    suppresses the KMRSP (`res = SRT_CMD_NONE`, log: "rejecting per enforced
    encryption"), the connection stays up, and the undecryptable KK≠0 data packets
    are dropped (§3.2). **This — ignore the KMREQ, drop encrypted data — is the
    1.4.4-faithful behavior to implement.**
  - Permissive mode (`ENFORCEDENCRYPTION=false`) replies with
    `UMSG_EXT`/`SRT_CMD_KMRSP` whose CIF is **one 32-bit word = KM state
    `SRT_KM_S_NOSECRET` (3)** (wire payload confirmed: `srtlen = 1`, word 0 =
    `m_RcvKmState`, **sender-host-endian — little-endian in practice**, because
    the KM double-swap cancellation applies to this word too; see
    encryption.md §5.1).
  (This situation is unreachable when the handshake correctly rejects encryption
  mismatches — see the handshake doc for `SRT_KM_S_*` values and rejection rules.)
- Unknown subtypes: ignore silently (libsrt forwards them to the congestion
  controller / packet filter, which is out of scope).

---

## 6. Timestamp semantics

- 32-bit unsigned count of **microseconds since the sending socket's start time**, put in
  header word 2 of *every* packet sent (data and control, including handshakes).
- "Start time" in libsrt 1.4.4 = the moment the socket was opened for connecting
  (`CUDT::open()` sets `m_stats.tsStartTime`) — i.e. slightly *before* the handshake
  completes. The draft says "the time the SRT connection was established"; the
  difference is harmless because the receiver never interprets timestamps absolutely: it
  establishes a time base from the handshake/first packets and tracks drift (TSBPD doc).
  Formula: `TS = (now − start_time) mod 2^32` µs.
- **Data packets, live mode:** the timestamp is the packet's *origin time* (when the
  application submitted the payload / it was scheduled into the send buffer), not the
  moment the datagram leaves the wire. **Retransmitted packets carry the original
  timestamp of the packet**, never the retransmission time — TSBPD depends on this.
  If a configured source time predates the start time, libsrt falls back to `now`.
- **Control packets:** timestamp is set to `now` (relative to start time) at send. The
  ACKACK timestamp is additionally used by the peer for drift tracking.
- **Wraparound:** 2^32 µs = 4294.967296 s ≈ **71 min 35 s** (libsrt comment:
  "01h11m35s"; `MAX_TIMESTAMP = 0xFFFFFFFF`). Any connection living longer than that
  sees timestamps wrap. Implications:
  - the sender just lets the 32-bit value wrap naturally (mod-2^32 arithmetic);
  - the receiver's TSBPD must detect and handle wrap: libsrt enters a "wrap check
    period" when timestamps arrive in the last 30 s before wrap
    (`TSBPD_WRAP_PERIOD = 30_000_000` µs) and adds 2^32 µs to the epoch base once small
    timestamps reappear. Details in the TSBPD sibling doc — but the *packet* layer must
    expose the timestamp as raw `u32` and never widen it lossily.

---

## 7. Destination Socket ID (header word 3) per situation

Each SRT socket has a 32-bit Socket ID (libsrt generates them from a random-seeded
decreasing counter; value `0` is reserved, never a real socket ID). Peers learn each
other's IDs from the `SRT Socket ID` field inside the handshake CIF.

| Situation | Destination Socket ID value |
|---|---|
| Caller → listener, INDUCTION request | **0** (marks "connection request") |
| Caller → listener, CONCLUSION request | **0** in libsrt 1.4.4 caller–listener mode (see divergence below) |
| Listener → caller, INDUCTION response | caller's socket ID (taken from the `SRT Socket ID` CIF field of the request) |
| Listener → caller, CONCLUSION response (and handshake rejection responses) | caller's socket ID |
| Any packet on an established connection (data, ACK, NAK, KEEPALIVE, SHUTDOWN, …) | **peer's** socket ID, always (libsrt sets `m_PeerID` on every outgoing packet) |
| Repeated/late CONCLUSION handshake received on an established socket — the response | peer's socket ID |

**Divergence (draft & `handshake.md` vs libsrt 1.4.4):** both documents state the
caller's CONCLUSION request should carry the listener's socket ID learned during
induction. **libsrt 1.4.4 actually sends 0** in caller–listener mode
(`request.m_iID = !bRendezvous ? 0 : m_ConnRes.m_iID` — only *rendezvous* uses the
peer's ID). The libsrt listener *requires* this: its receive queue dispatches on
Destination Socket ID — `0` → connection-request handler (which asserts `m_iID == 0`),
non-zero → lookup of an existing/connecting socket. Sending the listener's ID in a
CONCLUSION would mis-route the packet. **This implementation MUST send 0 in both
INDUCTION and CONCLUSION requests, and as listener MUST route all dst-ID-0 packets to
connection-request processing.**

Receive-side dispatch rules (mirroring libsrt `CRcvQueue::worker`):

- `dst == 0` → must be a HANDSHAKE control packet (connection request); anything else
  with `dst == 0` is discarded.
- `dst != 0` → deliver to the socket with that ID, additionally verifying the source
  address matches that socket's peer address; if no such socket exists, discard
  (optionally, libsrt may generate a SHUTDOWN for HSv4 compat — not required).

---

## 8. Quick reference — constants

| Constant | Value | Meaning |
|---|---|---|
| Header size | 16 bytes | all SRT packets |
| `F` bit mask (word 0) | `0x8000_0000` | 1 = control |
| Control type mask | `(word0 >> 16) & 0x7FFF` | |
| Subtype mask | `word0 & 0xFFFF` | |
| Data seq mask | `0x7FFF_FFFF` | 31-bit, mod-2^31 arithmetic |
| PP / O / KK / R masks | `0xC000_0000` / `0x2000_0000` / `0x1800_0000` / `0x0400_0000` | word 1, data |
| Message number mask | `0x03FF_FFFF` | 26-bit, starts at 1, wraps to 1, 0 = unknown |
| NAK range-start flag | `0x8000_0000` | on the `lo` word |
| Light ACK CIF size | 4 bytes | detection is by length |
| Small ACK CIF size | 16 bytes | |
| Full ACK CIF size | 24 or 28 bytes (send 28) | |
| ACK number max | `0x7FFF_FFFF`, wraps to 0 | first ACK sent = 1 |
| Full ACK period | 10 ms (`COMM_SYN_INTERVAL_US = 10_000` µs) | |
| Light ACK trigger | every 64 packets between timer ACKs | |
| ACKACK throttle | > 10 ms since last, or duplicate ACK number | |
| NAK periodic interval (live) | `(SRTT + 4·RTTVar)/2` µs, floor 20 ms | plus immediate NAK on gap detection |
| Keepalive period | 1 s idle (`COMM_KEEPALIVE_PERIOD_US`) | |
| Initial RTT / RTTVar | 100 ms / 50 ms | |
| Flow window floor advertised in ACK | 2 packets | |
| Timestamp wrap | 2^32 µs ≈ 71 min 35 s | TSBPD wrap period 30 s |
| Max payload | 1456 bytes (default live payload 1316) | |
| Handshake magic (induction Extension Field) | `0x4A17` | handshake doc |
