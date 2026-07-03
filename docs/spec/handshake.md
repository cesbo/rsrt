# SRT HSv5 Caller–Listener Handshake

Scope: HSv5 caller–listener handshake only, LIVE transmission mode, unencrypted
implementation. Interop target: **libsrt 1.4.4** (`srt-live-transmit`).

Sources:

* IETF draft `draft-sharabayko-srt-01` (2021-09-07; latest revision, expired, never
  published as an RFC) — "the draft" below.
* Haivision `docs/features/handshake.md` (master) — "handshake.md" below.
* libsrt **v1.4.4** source (`srtcore/handshake.{h,cpp}`, `core.cpp`, `queue.cpp`,
  `common.cpp`, `crypto.cpp`, `socketconfig.h`, `apps/transmitmedia.cpp`) — "libsrt"
  below. Where the draft and libsrt disagree, **libsrt 1.4.4 behavior wins**; every
  such difference is flagged explicitly.

Out of scope (mentioned only where a graceful reject/ignore is required): rendezvous
mode, HSv4, file/messaging mode, encryption key material contents (KM/HaiCrypt),
bonding/groups, packet filter/FEC.

---

## 1. Packet framing and byte order

A handshake packet is an SRT **control packet**: a 16-byte SRT header followed by the
Control Information Field (CIF).

**Byte order rule:** every 32-bit word of the SRT header AND of a control packet's
payload (CIF, extension headers, extension payload words) is serialized in **network
byte order (big-endian)**. libsrt converts the whole control payload with
per-32-bit-word `htonl`/`ntohl` on send/receive (`CPacket::toNL()/toHL()`, called from
`CChannel::sendto/recvfrom`). The consequences of this per-word swap for byte-string
data (Peer IP Address, StreamID) are described in §2.2 and §4.4 — those fields end up
**byte-reversed within each 32-bit word** relative to their natural byte-string order.

Control header for a handshake packet (byte offsets from start of UDP payload):

| Offset | Size | Field | Value for handshake |
|-------:|-----:|-------|---------------------|
| 0 | 2 | `F` bit (MSB) + Control Type | `F=1`, Control Type = `0x0000` (HANDSHAKE) → bytes `80 00` |
| 2 | 2 | Subtype | `0x0000` |
| 4 | 4 | Type-specific Information | `0` (unused for handshake) |
| 8 | 4 | Timestamp | microseconds since the **sender's** socket creation time (u32, wraps) |
| 12 | 4 | Destination Socket ID | see per-message tables in §5; `0` = connection request |

The Timestamp of the CONCLUSION request/response is load-bearing: each side computes
the peer's time base as `peer_start_time = now - packet.timestamp` when processing
HSREQ/HSRSP (libsrt `processSrtMsg_HSREQ/HSRSP`). It is later used by TSBPD. Fill it
correctly in every handshake packet.

The CIF starts at UDP payload offset 16. The fixed part of the handshake CIF is
exactly **48 bytes** (libsrt `CHandShake::m_iContentSize = 48`); extensions follow
immediately after. So an INDUCTION packet is a 64-byte UDP payload.

---

## 2. Handshake CIF layout

Offsets below are relative to the start of the CIF. All fields are unsigned 32-bit
big-endian unless stated otherwise.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 4 | Version |
| 4  | 2 | Encryption Field |
| 6  | 2 | Extension Field |
| 8  | 4 | Initial Packet Sequence Number (ISN) |
| 12 | 4 | Maximum Transmission Unit Size (MTU / "MSS") |
| 16 | 4 | Maximum Flow Window Size |
| 20 | 4 | Handshake Type |
| 24 | 4 | SRT Socket ID |
| 28 | 4 | SYN Cookie |
| 32 | 16 | Peer IP Address (4 × 32-bit words) |
| 48 | var | Extensions (sequence of TLV blocks, §4) — only in HSv5 CONCLUSION |

Field semantics:

* **Version** — handshake protocol version. `4` = HSv4/UDT legacy, `5` = HSv5.
  Special value `0` in a received CONCLUSION-phase handshake marks a rejected
  handshake (libsrt: "HS VERSION = 0, meaning the handshake has been rejected",
  reason `SRT_REJ_PEER`). Values > 5 are reserved.
* **Encryption Field** (upper 16 bits of the legacy UDT "Type" word) — advertised
  cipher family/key size ("PBKEYLEN"):

  | Value | Meaning |
  |------:|---------|
  | 0 | no encryption advertised |
  | 2 | AES-128 (PBKEYLEN 16) |
  | 3 | AES-192 (PBKEYLEN 24) |
  | 4 | AES-256 (PBKEYLEN 32) |

  An unencrypted implementation always sends `0` and ignores the received value.
* **Extension Field** (lower 16 bits of the legacy "Type" word) — meaning depends on
  message:
  * caller INDUCTION request: `2` (legacy UDT `UDT_DGRAM` socket type; libsrt 1.4.4
    listener does **not** verify it in the induction request),
  * listener INDUCTION response: magic `0x4A17` (`SRT_MAGIC_CODE`),
  * CONCLUSION request/response: bitmask of attached extension groups:

    | Bit | Name | Meaning |
    |-----|------|---------|
    | `0x1` | `HSREQ` | HSREQ/HSRSP extension present |
    | `0x2` | `KMREQ` | KMREQ/KMRSP extension present |
    | `0x4` | `CONFIG` | one or more config extensions present (SID, CONGESTION, FILTER, GROUP) |

    Must be non-zero in an HSv5 CONCLUSION (libsrt rejects `ext_flags == 0` with
    `SRT_REJ_ROGUE`).
* **Initial Packet Sequence Number** — sequence number of the first data packet;
  `CHandShake::valid()` requires `0 <= ISN < 0x7FFFFFFF` (`CSeqNo::m_iMaxSeqNo`).
  Caller generates it randomly (`generateISN()`; generate in `[0, 0x7FFFFFFE]` to
  stay within the peer's validity check). **In caller–listener mode the
  listener does NOT generate its own ISN**: it adopts the caller's ISN for its own
  sending direction and echoes it in the CONCLUSION response
  (libsrt `acceptAndRespond`: `m_iISN = w_hs.m_iISN; // use peer's ISN and send it
  back for security check`). The caller verifies the echoed ISN and aborts the
  connection with a security error if it does not match its own
  (`m_ConnRes.m_iISN != m_iISN → MJ_SETUP/MN_SECURITY`). Both directions of the
  connection therefore start from the caller's ISN.
* **Maximum Transmission Unit Size** — the `SRTO_MSS` value = maximum size of one
  UDP *IP packet*, including IP+UDP headers. Default `1500`. Minimum accepted: `32`
  (`valid()`). Negotiation: effective MSS = `min(caller, listener)`; the listener
  computes the min and puts it into the CONCLUSION response; the caller adopts the
  response value as-is. Maximum SRT payload per packet =
  `MSS - 28 (IPv4+UDP) - 16 (SRT header)` = 1456 for MSS 1500.
* **Maximum Flow Window Size** — max number of unacknowledged packets in flight the
  *sender of this handshake* allows the peer to have toward it; libsrt fills it with
  `flightCapacity() = min(SRTO_RCVBUF_in_packets, SRTO_FC)` = `min(8192, 25600)` =
  **8192** by default. Minimum accepted: `2` (`valid()`). The receiver of the
  handshake uses the received value as its send-side flow window.
* **Handshake Type** — see §3.
* **SRT Socket ID** — socket ID of the *sender* of this handshake message. Must be
  non-zero (0 in a packet header destination means "connection request"). See §5 for
  the induction-response quirk.
* **SYN Cookie** — see §6. `0` in the induction request; listener-generated value in
  the induction response; echoed by the caller in the conclusion request; in the
  conclusion response libsrt 1.4.4 simply leaves the field as received (i.e. it
  echoes the caller's cookie back; the draft says "without the cookie"). Receivers
  ignore the cookie in the conclusion response.
* **Peer IP Address** — see §2.2.

### 2.1 CIF validation (`CHandShake::valid()`, applied by the listener to CONCLUSION)

Reject (as ROGUE, silently — no response is sent for this particular check) unless:

```
version >= 4
0 <= ISN < 0x7FFFFFFF   (libsrt: m_iISN >= 0 && m_iISN < CSeqNo::m_iMaxSeqNo)
MSS >= 32
FlowWindow >= 2
```

Also: any packet routed to the handshake processor that is not a control packet of
type HANDSHAKE, or whose payload is shorter than 48 bytes, is rejected/ignored.

### 2.2 Peer IP Address encoding (exact)

Semantics (libsrt 1.4.4): the field carries the IP address of the **destination of
the packet** — i.e. the address of the machine the sender is sending *to* (the caller
puts the listener's address; the listener puts the caller's address). The receiving
side stores it as "my own address as seen by the peer" (`m_piSelfIP`), used only
informationally (to synthesize a local address when the socket is bound to
`0.0.0.0`). It is **never validated**, and a wrong value does not break the
handshake against libsrt.

> Difference: the draft (§3.2.1) says "IPv4 or IPv6 address of the packet's
> *sender*". libsrt 1.4.4 actually writes the *destination* (peer) address as
> described above. Since the field is unvalidated, either interpretation
> interoperates; implement the libsrt behavior.

Byte layout: 4 × 32-bit words. For IPv4, only word 0 is used and words 1–3 MUST be
zero. Wire encoding produced by libsrt on little-endian hosts (i.e. every real-world
deployment):

* libsrt copies the raw network-order address bytes into host `uint32_t`s
  (`ip[0] = sin_addr.s_addr` for IPv4; for IPv6 each `ip[i]` is assembled from
  `s6_addr[4i..4i+3]` with `s6_addr[4i]` as the **least significant** byte), and then
  the global per-word `htonl` of §1 is applied on send.
* Net effect on the wire: **each 4-byte group of the address appears byte-reversed
  inside its 32-bit word.**

Worked IPv4 example — address `192.168.1.10` (network-order bytes `C0 A8 01 0A`):

```
wire bytes of Peer IP word 0 :  0A 01 A8 C0
wire words 1..3              :  00 00 00 00  (x3)
```

Equivalently: read the wire word as a big-endian u32 (`0x0A01A8C0`) — that u32, when
stored little-endian, yields the network-order address bytes.

Encoding rule for an implementation (endian-independent formulation):

```
encode: word[i] (u32, sent big-endian) = u32::from_le_bytes(addr_bytes[4i .. 4i+4])
decode: addr_bytes[4i .. 4i+4]         = u32_value_of_word[i].to_le_bytes()
```

where `addr_bytes` is the address in standard network order (4 bytes IPv4 /
16 bytes IPv6).

> Note (verified in v1.4.4 `common.cpp`, `CIPAddress::ntop/pton`): libsrt
> raw-loads `s_addr` for IPv4 (`ip[0] = sin_addr.s_addr`), so a big-endian libsrt
> host would emit the IPv4 word in straight network order — the wire format is
> host-endian-dependent in libsrt for IPv4. No big-endian build was runtime-tested,
> but the code path is unambiguous. All interop targets are little-endian; use the
> little-endian formulation above. (For IPv6 the assembly is byte-explicit —
> `s6_addr[4i]` is the least significant byte of `ip[i]` — so the encoding above is
> exact regardless of host endianness.)

---

## 3. Handshake Type values

Signed values transmitted as u32 (two's complement, big-endian):

| Wire value (u32) | As i32 | Name | Use |
|------------------|-------:|------|-----|
| `0x00000001` | 1 | `INDUCTION` | phase 1 request and response (caller↔listener) |
| `0x00000000` | 0 | `WAVEAHAND` | rendezvous only — **out of scope**; a listener receiving it treats it as a non-induction request: cookie check fails → silently ignored |
| `0xFFFFFFFF` | −1 | `CONCLUSION` | phase 2 request and response |
| `0xFFFFFFFE` | −2 | `AGREEMENT` | rendezvous only — never sent in caller–listener HSv5 |
| `0xFFFFFFFD` | −3 | `DONE` | internal libsrt state marker, never legitimately on the wire in this mode |

### 3.1 Rejection codes

When a connection is rejected, the responding handshake carries
`Handshake Type = 1000 + reason` (`URQ_FAILURE_TYPES = 1000`). A received handshake
type value **> 1000** must be interpreted as a rejection with
`reason = value − 1000`. (libsrt's check is strictly `> 1000`, so wire value exactly
1000 is not treated as a rejection; never send 1000.)

`SRT_REJ_*` reasons (libsrt 1.4.4 `srt.h`; draft Table 7 lists 1000–1015 and agrees):

| Reason | Code | Wire HS Type | Meaning |
|--------|-----:|-------------:|---------|
| `SRT_REJ_UNKNOWN` | 0 | 1000 | unknown/in-progress marker (not sent) |
| `SRT_REJ_SYSTEM` | 1 | 1001 | system function error |
| `SRT_REJ_PEER` | 2 | 1002 | rejected by peer |
| `SRT_REJ_RESOURCE` | 3 | 1003 | resource allocation failure |
| `SRT_REJ_ROGUE` | 4 | 1004 | incorrect data in handshake |
| `SRT_REJ_BACKLOG` | 5 | 1005 | listener's backlog exceeded |
| `SRT_REJ_IPE` | 6 | 1006 | internal program error |
| `SRT_REJ_CLOSE` | 7 | 1007 | socket is closing |
| `SRT_REJ_VERSION` | 8 | 1008 | peer version too old / unsupported |
| `SRT_REJ_RDVCOOKIE` | 9 | 1009 | cookie collision (also the code used internally for a wrong caller cookie, but that case is *silently ignored*, not answered) |
| `SRT_REJ_BADSECRET` | 10 | 1010 | wrong passphrase |
| `SRT_REJ_UNSECURE` | 11 | 1011 | password required, or unexpected |
| `SRT_REJ_MESSAGEAPI` | 12 | 1012 | STREAM flag collision (stream vs message API) |
| `SRT_REJ_CONGESTION` | 13 | 1013 | incompatible congestion controller |
| `SRT_REJ_FILTER` | 14 | 1014 | incompatible packet filter |
| `SRT_REJ_GROUP` | 15 | 1015 | incompatible group |
| `SRT_REJ_TIMEOUT` | 16 | 1016 | connection timeout (set locally; not normally sent on the wire) |

Extended ranges (1.4.4): `SRT_REJC_PREDEFINED = 1000` and `SRT_REJC_USERDEFINED =
2000` offsets exist for application/listener-callback rejections, giving wire values
`>= 2000` (server codes) and `>= 3000` (user codes). Treat any received value
`> 1000` as a rejection and surface `value − 1000` as the reason code.

The rejection response packet from the listener is the received 48-byte CONCLUSION
CIF echoed back with only `Handshake Type` replaced by the failure value, no
extensions, header Destination Socket ID = caller's socket ID.

---

## 4. Extension encoding

Extensions appear only in CONCLUSION request/response (HSv5), immediately after the
48-byte CIF, packed back-to-back with no padding between blocks. Each block:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 2 | Extension Type (u16, big-endian) |
| 2 | 2 | Extension Length (u16, big-endian) — length of the *contents only*, in **4-byte words** |
| 4 | 4 × Length | Extension Contents |

(In libsrt the type+length pair is one 32-bit word: `HS_CMDSPEC_CMD = bits 31..16`,
`HS_CMDSPEC_SIZE = bits 15..0`.)

Extension Type values:

| Value | Name | Covered by Extension Field bit |
|------:|------|-------------------------------|
| 1 | `SRT_CMD_HSREQ` | `HSREQ (0x1)` |
| 2 | `SRT_CMD_HSRSP` | `HSREQ (0x1)` |
| 3 | `SRT_CMD_KMREQ` | `KMREQ (0x2)` |
| 4 | `SRT_CMD_KMRSP` | `KMREQ (0x2)` |
| 5 | `SRT_CMD_SID` | `CONFIG (0x4)` |
| 6 | `SRT_CMD_CONGESTION` | `CONFIG (0x4)` |
| 7 | `SRT_CMD_FILTER` | `CONFIG (0x4)` |
| 8 | `SRT_CMD_GROUP` | `CONFIG (0x4)` |

Order sent by libsrt 1.4.4 (`createSrtHandshake`): **HSREQ/HSRSP first**, then SID
(request direction only, if StreamID configured), then CONGESTION (only if not
"live"), then FILTER (only if configured), then GROUP (bonding builds only), then
**KMREQ/KMRSP last**. A receiver must not depend on order: libsrt itself scans the
block list for each type. Unknown/unsupported block types must be **skipped**
(libsrt skips them; e.g. a non-bonding build skips `SRT_CMD_GROUP`).

Receiver-side requirements (libsrt listener, HSv5 CONCLUSION):

* `Extension Field == 0` → reject `SRT_REJ_ROGUE`.
* `HSREQ` bit set but no HSREQ/HSRSP block found → reject `SRT_REJ_ROGUE`.
* `KMREQ` bit set but no KMREQ/KMRSP block found → reject `SRT_REJ_ROGUE`.
* HSREQ block shorter than 3 words → reject `SRT_REJ_ROGUE`.
* SID contents length 0 or > 512 bytes → reject.
* CONGESTION or FILTER block repeated → reject (`SRT_REJ_ROGUE` / `SRT_REJ_FILTER`).

### 4.1 HSREQ / HSRSP payload (3 × 32-bit words, Extension Length = 3)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | SRT Version |
| 4 | 4 | SRT Flags |
| 8 | 2 | **Receiver** TSBPD Delay, ms (upper half-word — first on the wire) |
| 10 | 2 | **Sender** TSBPD Delay, ms (lower half-word) |

* **SRT Version** = `major * 0x10000 + minor * 0x100 + patch`. libsrt 1.4.4 sends
  `0x010404`. In HSv5 the value MUST be `>= 0x010300` (`SRT_VERSION_FEAT_HSv5`),
  otherwise the peer rejects with `SRT_REJ_ROGUE`. libsrt also rejects with
  `SRT_REJ_VERSION` if the value is below its configured minimum
  (`SRTO_MINVERSION`, default `0x010000`).
* **Latency half-words** (libsrt `SRT_HS_LATENCY_RCV = bits 31..16`,
  `SRT_HS_LATENCY_SND = bits 15..0` of the third word): the *Receiver TSBPD Delay*
  is the latency the sender of this extension wants to use **when receiving**; the
  *Sender TSBPD Delay* is the latency it proposes for **its peer's receiving**
  direction (i.e. for the data this side sends). See §4.2 for negotiation.

**SRT Flags** (word 2):

| Bit | Name (draft / libsrt) | A live-mode unencrypted implementation… |
|-----|------------------------|------------------------------------------|
| `0x00000001` | `TSBPDSND` / `SRT_OPT_TSBPDSND` | MUST set in HSREQ (we send with TSBPD timestamps); in HSRSP set iff the HSREQ had `TSBPDRCV` set |
| `0x00000002` | `TSBPDRCV` / `SRT_OPT_TSBPDRCV` | MUST set in HSREQ and (if we receive with TSBPD, which live mode does) in HSRSP |
| `0x00000004` | `CRYPT` / `SRT_OPT_HAICRYPT` | MUST set always (legacy capability flag: "understands the KK field"); libsrt always sets it, even unencrypted |
| `0x00000008` | `TLPKTDROP` / `SRT_OPT_TLPKTDROP` | MUST set (live default: too-late packet drop on) |
| `0x00000010` | `PERIODICNAK` / `SRT_OPT_NAKREPORT` | MUST set (live default: periodic NAK reports on) |
| `0x00000020` | `REXMITFLG` / `SRT_OPT_REXMITFLG` | MUST set in HSREQ; in HSRSP set iff peer set it (it did, for any peer ≥ 1.2.0) |
| `0x00000040` | `STREAM` / `SRT_OPT_STREAM` | MUST be **clear** for live mode (live = message API). The responder rejects with `SRT_REJ_MESSAGEAPI` (1012) if this bit does not match its own mode |
| `0x00000080` | `PACKET_FILTER` / `SRT_OPT_FILTERCAP` | libsrt 1.4.4 always sets it (capability advertisement). An implementation without packet-filter support SHOULD leave it clear — then a libsrt peer will not attach a filter config in its HSRSP |

libsrt 1.4.4 with live defaults sends `0xBF` (all of the above except `STREAM`).
A conforming unencrypted live implementation without filter support sends `0x3F`.
The only flag *checked for equality* by libsrt is `STREAM`; `REXMITFLG`,
`PERIODICNAK`, `TLPKTDROP`, `TSBPD*` toggle per-connection features; `CRYPT` and
`PACKET_FILTER` are pure capability bits.

### 4.2 Latency negotiation

Configuration inputs per side: `SRTO_RCVLATENCY` (own receive latency; **default
120 ms** in live mode, `SRT_LIVE_DEF_LATENCY_MS = 120`) and `SRTO_PEERLATENCY`
(latency proposed for the peer's receiving direction; **default 0**).
(`SRTO_LATENCY` is an API alias that sets both.)

There is no protocol-level minimum; 120 ms is only the default of
`SRTO_RCVLATENCY`. The rule at every step is `max()`:

1. **Caller HSREQ**: `RcvTsbpdDelay = caller.SRTO_RCVLATENCY` (120),
   `SndTsbpdDelay = caller.SRTO_PEERLATENCY` (0). Sent only when TSBPD is on
   (`TSBPDSND`/`TSBPDRCV` flags set); if TSBPD flags are clear the half-words are 0
   and ignored.
2. **Listener on HSREQ** (`processSrtMsg_HSREQ`):
   * effective latency for direction **caller→listener** (listener receives):
     `listener.rcv_latency = max(listener.SRTO_RCVLATENCY, HSREQ.SndTsbpdDelay)`
   * effective latency for direction **listener→caller** (caller receives):
     `listener.peer_latency = max(listener.SRTO_PEERLATENCY, HSREQ.RcvTsbpdDelay)`
3. **Listener HSRSP**: `RcvTsbpdDelay = listener.rcv_latency`,
   `SndTsbpdDelay = listener.peer_latency` (the `SND` half is included iff the HSREQ
   had `TSBPDRCV` set). These are final — no further negotiation.
4. **Caller on HSRSP** (`processSrtMsg_HSRSP`): adopts
   `caller.rcv_latency = HSRSP.SndTsbpdDelay` (its TSBPD delay for incoming data,
   used only if HSRSP has `TSBPDSND` set) and
   `caller.peer_latency = HSRSP.RcvTsbpdDelay` (peer's receive latency, used if
   HSRSP has `TSBPDRCV` set).

With all defaults on both sides the effective latency is **120 ms in both
directions**.

### 4.3 KMREQ / KMRSP (documented only for graceful rejection)

Payload of KMREQ is the HaiCrypt KM message (opaque here). Note its byte-order
quirk: KM material is a byte string in network order end-to-end; libsrt pre-swaps it
per-word (`HtoNLA`) exactly to cancel the global per-word swap of §1 — i.e. **on the
wire the KM message bytes appear in their natural order**, unlike SID (§4.4).

An error KMRSP has Extension Length = 1 and a single 32-bit word holding the KM
state code: `SRT_KM_S_UNSECURED = 0`, `SECURING = 1`, `SECURED = 2`,
`NOSECRET = 3`, `BADSECRET = 4`. See §9.

### 4.4 StreamID (SID) extension

* Sent **only by the initiator (caller)**, together with HSREQ, when
  `SRTO_STREAMID` is set. The listener never sends SID back.
* Content: **arbitrary byte string** — libsrt does not require (or validate)
  UTF-8; a non-UTF-8 StreamID is legal on the wire and accepted by a 1.4.4 peer.
  No NUL terminator, **maximum 512 bytes** (`MAX_SID_LENGTH = 512`). Receiver
  rejects length 0 or > 512. (Sender-side libsrt additionally caps it at
  `payload_size/2` as a sanity check.)
* Extension Length = `ceil(strlen/4)`; the last word is padded with `0x00` bytes.
  The receiver recovers the length by trimming trailing NULs (embedded NULs are
  therefore impossible).

**Wire byte-shuffling rule:** the padded string is packed into 32-bit words, and
each word's bytes appear on the wire in **reversed order** (consequence of libsrt
storing the words "pre-swapped to little endian" — `HtoILA` — and the global
per-word big-endian swap of §1). Same encode/decode rule as Peer IP:

```
wire_word[i] (u32, big-endian on wire) = u32::from_le_bytes(padded_sid[4i..4i+4])
```

Worked example — StreamID `"abcdefg"` (7 bytes, padded to 8):

```
padded bytes :  61 62 63 64  65 66 67 00      ("abcd" "efg\0")
wire bytes   :  64 63 62 61  00 67 66 65      ("dcba" "\0gfe")
ext header   :  00 05 00 02                   (type=5 SID, length=2 words)
```

(handshake.md's example: `"STREAM"` → padded `"STREAM\0\0"` → wire `"ERTS\0\0MA"`.)

### 4.5 CONGESTION extension

String-typed, same per-word byte-reversal encoding as SID. Value is the congestion
controller name: `"live"` or `"file"`. **libsrt never sends this extension when the
controller is "live"** (the default); absence means "live". Receiver rule: if the
extension is present and its value differs from our controller ("live"), reject with
`SRT_REJ_CONGESTION` (1013). So a live-only implementation: never send it; reject
any received value other than `"live"`.

### 4.6 FILTER and GROUP extensions

* `SRT_CMD_FILTER` (7): packet-filter (FEC) config string (same string encoding).
  An implementation without filter support: do not advertise `PACKET_FILTER` flag,
  never send this extension, and if it is received reject with `SRT_REJ_FILTER`
  (1014). (libsrt 1.4.4 only sends it when explicitly configured with
  `SRTO_PACKETFILTER`; `srt-live-transmit` does not by default.)
* `SRT_CMD_GROUP` (8): bonding groups. Default (non-bonding) libsrt 1.4.4 builds
  **silently skip** this block; do the same (ignore). A caller that *requires*
  bonding will itself drop the connection when no GROUP block comes back.

---

## 5. The caller–listener sequence

```
CALLER                                        LISTENER
  |--- INDUCTION request  (48-byte CIF) --------->|   (stateless)
  |<-- INDUCTION response (48-byte CIF) ----------|   (stateless, cookie set)
  |--- CONCLUSION request (CIF + HSREQ [+SID]) -->|   (cookie verified, socket created)
  |<-- CONCLUSION response (CIF + HSRSP) ---------|   (connection established)
```

There is no third leg (no AGREEMENT) in caller–listener mode. The listener considers
the connection established when it sends the CONCLUSION response; the caller when it
receives and validates that response.

### 5.1 INDUCTION request (caller → listener)

| Field | Value |
|-------|-------|
| header Destination Socket ID | **0** (means "connection request") |
| header Timestamp | µs since caller socket creation |
| Version | **4** (mandatory — HSv4 compatibility; a value of 5 here is wrong) |
| Encryption Field | 0 |
| Extension Field | **2** (`UDT_DGRAM`; listener 1.4.4 does not check it) |
| ISN | caller's random ISN (also not interpreted by the listener at this stage) |
| MTU | caller's MSS (default 1500) |
| Max Flow Window | caller's flight capacity (default 8192) |
| Handshake Type | `0x00000001` INDUCTION |
| SRT Socket ID | caller's socket ID (non-zero) |
| SYN Cookie | **0** |
| Peer IP Address | listener's address, encoded per §2.2 |
| Extensions | none (total CIF = 48 bytes) |

### 5.2 INDUCTION response (listener → caller)

The listener is completely stateless here: it takes the received CIF and modifies
only the fields below, echoing everything else verbatim (ISN, MTU, Flow Window,
Peer IP and — see the warning — SRT Socket ID stay as received):

| Field | Value |
|-------|-------|
| header Destination Socket ID | caller's socket ID (from the request's CIF SRT Socket ID) |
| header Timestamp | µs since **listener** socket creation |
| Version | **5** (tells the caller "I am HSv5") |
| Encryption Field | advertised PBKEYLEN: 0 for an unencrypted listener (libsrt: `SRTO_PBKEYLEN` value ⇒ 2/3/4) |
| Extension Field | magic **`0x4A17`** |
| Handshake Type | `0x00000001` INDUCTION (unchanged) |
| SYN Cookie | listener-generated cookie (§6) |
| SRT Socket ID | **unchanged — still the caller's socket ID** (see below) |
| Extensions | none (48 bytes) |

> **Difference (important):** the draft and handshake.md say the induction response
> carries the *listener's* Socket ID in the CIF. libsrt 1.4.4
> (`processConnectRequest`, induction branch) modifies only Cookie, Version and the
> Type word and sends the rest back verbatim — so the CIF SRT Socket ID in the real
> induction response is the **caller's own ID echoed back**. Consequently the caller
> MUST NOT interpret this field in the induction response, and a listener
> implementation should simply echo (either behavior interops, since no libsrt
> caller reads it).

Caller processing of the induction response:

* Accept only if Version == 5 (Version 4 would mean an HSv4 listener — out of scope;
  abort with `SRT_REJ_VERSION` semantics). Precision: libsrt's own check is
  `version > 4` — any value ≥ 5 is taken as "HSv5-capable"; an exact `== 5` check is
  fine, no real listener sends anything else.
* Check Extension Field == `0x4A17`. **libsrt 1.4.4 only logs a warning and
  continues if the magic is absent** (the draft says "reject"). Matching libsrt:
  warn and continue.
* Encryption Field: an unencrypted caller ignores it (libsrt without a passphrase
  just records the advertised PBKEYLEN).
* Save the cookie; proceed to CONCLUSION immediately (do not wait for the 250 ms
  tick).

### 5.3 CONCLUSION request (caller → listener)

| Field | Value |
|-------|-------|
| header Destination Socket ID | **0** (libsrt 1.4.4 caller sends 0 in caller–listener mode — see below) |
| header Timestamp | µs since caller socket creation (used by listener for TSBPD time base) |
| Version | **5** |
| Encryption Field | advertised PBKEYLEN; **0** for an unencrypted caller |
| Extension Field | extension bits actually attached: `0x1` (HSREQ) &#124; `0x4` if SID attached &#124; `0x2` if KMREQ attached. Typical unencrypted caller with StreamID: **`0x0005`**; without StreamID: **`0x0001`** |
| ISN | caller's ISN (same one it will use for data; will be echo-verified) |
| MTU | caller's MSS (1500) |
| Max Flow Window | caller's flight capacity (8192) |
| Handshake Type | `0xFFFFFFFF` CONCLUSION |
| SRT Socket ID | caller's socket ID |
| SYN Cookie | the cookie received in the induction response, verbatim |
| Peer IP Address | listener's address (§2.2) |
| Extensions | HSREQ (§4.1) [+ SID] [+ KMREQ] in that order |

> **Difference:** the draft/handshake.md say the destination socket ID of the
> CONCLUSION should be "the socket ID received in the induction phase". libsrt 1.4.4
> actually sends **0** in caller–listener mode, in both its blocking path
> (`startConnect`: `if (m_config.bRendezvous) reqpkt.m_iID = m_ConnRes.m_iID;` —
> i.e. left at 0 otherwise) and its async path (`processAsyncConnectRequest`:
> `request.m_iID = !m_config.bRendezvous ? 0 : m_ConnRes.m_iID;`). This is also the
> only value that works: the libsrt listener dispatches **only packets with
> destination ID 0** to connection-request processing (`CRcvQueue::worker`:
> `id == 0 → worker_ProcessConnectionRequest`). A CONCLUSION sent to a non-zero ID
> would never reach the listener. **Send 0.**

Listener processing of the CONCLUSION request, in order:

1. Payload shorter than 48 bytes, or not a HANDSHAKE control packet → reject
   `SRT_REJ_ROGUE` (no response sent).
2. `CHandShake::valid()` (§2.1) → on failure silently ignore (`SRT_REJ_ROGUE`).
   (Note: libsrt runs `valid()` *before* the cookie check.)
3. Compute `cookie(now)`; if it doesn't match, 1.4.4 recomputes a fallback cookie
   (in practice a useless *future*-minute one — see §6; this implementation should
   check `cookie(now − 1 minute)` instead); if neither matches → **silently
   ignore** (no response; internal reason `SRT_REJ_RDVCOOKIE`). This path also
   disposes of stray WAVEAHAND/AGREEMENT/etc.
4. Version check: 5 → HSv5 path; 4 → HSv4 path (out of scope; respond with
   rejection `SRT_REJ_VERSION` if not implementing HSv4 — note libsrt itself would
   accept HSv4 here, so this is a deliberate scope restriction); anything else
   (including 0) → rejection response `SRT_REJ_VERSION` (1008).
5. Backlog full → rejection `SRT_REJ_BACKLOG`; allocation failures →
   `SRT_REJ_RESOURCE`.
6. Parse extensions (§4): missing/short HSREQ → `SRT_REJ_ROGUE`; version/flag checks
   per §4.1 (`SRT_REJ_ROGUE`, `SRT_REJ_VERSION`, `SRT_REJ_MESSAGEAPI`); KM handling
   per §9; congestion per §4.5; filter per §4.6; compute latencies per §4.2.
7. Create the connection socket (new socket ID on the listener side), state:
   `peer_id = caller CIF Socket ID`, `peer_addr = UDP source address`,
   `ISN(send) = ISN(recv) = caller's ISN`, `MSS = min(own, caller's)`,
   `flow_window = caller's Max Flow Window`,
   `peer_start_time = now − packet.Timestamp` (µs).
8. Send the CONCLUSION response. From this moment the connection is live on the
   listener side.

### 5.4 CONCLUSION response (listener → caller)

| Field | Value |
|-------|-------|
| header Destination Socket ID | caller's socket ID |
| header Timestamp | µs since listener socket creation (caller uses it for TSBPD time base) |
| Version | **5** |
| Encryption Field | advertised PBKEYLEN; **0** for an unencrypted listener |
| Extension Field | `0x1` (HSRSP) [&#124; `0x2` if KMRSP attached]. Typical unencrypted: **`0x0001`** |
| ISN | **caller's ISN echoed back** (mandatory: libsrt caller aborts with a security error on mismatch) |
| MTU | `min(caller MSS, listener MSS)` — the negotiated value |
| Max Flow Window | listener's flight capacity (default 8192) |
| Handshake Type | `0xFFFFFFFF` CONCLUSION |
| SRT Socket ID | **the newly created (accepted) socket's ID on the listener side** — this becomes the caller's `peer_id` |
| SYN Cookie | libsrt echoes the received cookie (field is ignored by the caller; the draft says "no cookie") |
| Peer IP Address | caller's address (§2.2) |
| Extensions | HSRSP (§4.1) [+ KMRSP §4.3/§9] — never SID, never CONGESTION for "live" |

Caller processing of the CONCLUSION response:

1. If CIF Handshake Type > 1000 → rejected; reason = value − 1000; abort.
2. If Version == 0 → rejected by peer (`SRT_REJ_PEER`); abort. Version must be 5.
3. `valid()` check → `SRT_REJ_ROGUE` on failure.
4. **Security check: response ISN must equal the caller's own ISN**; otherwise
   abort (libsrt: `MJ_SETUP/MN_SECURITY`).
5. Parse HSRSP (must be present — Extension Field bit `0x1` and block type 2);
   adopt latencies per §4.2, flags per §4.1, `peer_start_time = now − Timestamp`.
6. Adopt: `peer_id = response CIF Socket ID`, `MSS = response MTU`,
   `flow_window = response Max Flow Window`, `rcv ISN = snd ISN = own ISN`.
7. Connection established; data packets may flow immediately.

### 5.5 Repeated CONCLUSION (lost response)

If the listener's CONCLUSION response is lost, the caller keeps retransmitting the
CONCLUSION request (§8). The listener, finding that a connection from this
`(peer address, peer socket ID)` already exists, does **not** create a second
socket: it re-crafts and re-sends the same CONCLUSION response (with HSRSP, and
KMRSP where applicable) from the existing accepted socket
(libsrt `processConnectRequest` → `newConnection` returns 0 → "sending REPEATED
handshake response"). Rule: *every* CONCLUSION request must be answered with a
CONCLUSION response as long as the connection exists.

The listener may also start receiving data packets addressed to the accepted socket
before the caller ever sees the response; that is normal.

---

## 6. SYN cookie

Purpose: the listener stays fully stateless until a CONCLUSION with a valid cookie
arrives (SYN-flood mitigation, RFC 4987 style).

libsrt 1.4.4 algorithm (`CUDT::bake`):

```
host  = numeric string of caller's IP  (getnameinfo NI_NUMERICHOST, e.g. "192.168.1.2")
port  = numeric string of caller's UDP port, e.g. "51000"
t     = minutes elapsed since the listener socket's start time   (int64)
        [+ static "distractor" counter, normally 0; − correction]
input = host + ":" + port + ":" + decimal(t)          e.g. "192.168.1.2:51000:17"
digest = MD5(input)                                    (RFC 1321)
cookie = first 4 bytes of digest, read as a native-endian i32
```

* The "secret" is effectively the listener's start time (minute counter);
  the exact algorithm is **implementation-private** — any stateless verifiable
  function of (source address, source port, secret, minute-granularity time) works,
  because the cookie is only generated and checked by the listener itself and merely
  echoed by the caller.
* Cookie must be non-zero in practice (0 is the "no cookie" marker in the induction
  request; an all-zero MD5 prefix is astronomically unlikely — libsrt doesn't
  special-case it).
* **Tolerance (1.4.4 quirk — verified in source):** when verifying a CONCLUSION,
  libsrt first checks the cookie of the *current* minute. On mismatch it recomputes
  via `bake(addr, cookie, -1)` — but 1.4.4's formula is
  `t = minutes + distractor − correction`, so `correction = −1` yields the **next**
  minute's cookie (`minutes + 1`), not the previous one (the code comment says
  "earlier"; the sign was fixed in later libsrt, where the formula is
  `… + correction`). Net effect in 1.4.4: only the *current-minute* cookie ever
  validates for a real caller; a CONCLUSION whose cookie was minted just before the
  listener's minute counter rolled over is silently ignored, the caller keeps
  retransmitting the same stale cookie (it never redoes INDUCTION), and the attempt
  dies at the 3 s connect timeout. Rare (window ≈ handshake RTT once per minute)
  but real. **This implementation (as listener): accept the current *or previous*
  minute's cookie** — the cookie is generated and checked only by the listener
  itself, so widening the window is interop-neutral and fixes the boundary case.
  Wrong cookie ⇒ silently ignored (no rejection response).

---

## 7. Connection identification after the handshake

* All post-handshake packets (data and control) carry
  `Destination Socket ID = peer's socket ID` (for the caller: the accepted-socket ID
  from the CONCLUSION response; for the listener side: the caller's socket ID).
* Incoming packets are dispatched by Destination Socket ID; the receiver then
  verifies that the UDP **source address and port** equal the connection's stored
  peer address — a mismatch is ignored as a spoofing attempt (libsrt
  `worker_ProcessAddressedPacket`: "CONSIDERED ATTACK ATTEMPT").
* Packets with Destination Socket ID = 0 continue to be routed to the listener's
  handshake processor (new connections on the same UDP port — SRT multiplexes many
  connections plus the listener on one socket; everything for one connection runs on
  the single 5-tuple established by the handshake).

---

## 8. Retransmission and timeouts

| Parameter | Value | Source |
|-----------|-------|--------|
| Handshake request retransmit period (caller; applies to both INDUCTION and CONCLUSION) | **250 ms** since last send, checked on every wakeup (blocking mode: `startConnect` loop "at most 1 request per 250ms"; async mode: `CRendezvousQueue::updateConnStatus`, exact 250 ms tick) | libsrt `core.cpp` / `queue.cpp` |
| Immediate transition send | on receiving the INDUCTION response the caller resets its "last request time" and sends the CONCLUSION at once | libsrt (`m_tsLastReqTime = 0`) |
| Overall connection timeout | **3 s** default (`SRTO_CONNTIMEO`, `DEF_CONNTIMEO_S = 3`); on expiry the caller gives up with `SRT_REJ_TIMEOUT` (local code; nothing sent) | libsrt `socketconfig.h` |
| Listener retransmissions | none — the listener only ever *responds*: induction response per induction request, conclusion response per conclusion request (§5.5), rejection response per invalid-but-answerable conclusion | libsrt |
| Listener state | none until a CONCLUSION with a valid cookie passes validation; then per-connection state keyed by (peer address, peer socket ID) | libsrt |

The caller retransmits whatever its current request state is: INDUCTION until a
valid induction response arrives, then CONCLUSION until the conclusion response
arrives or the 3 s budget is exhausted. Each retransmission carries a fresh
Timestamp. (A rejection response or Version=0 response terminates the attempt
immediately.)

---

## 9. Encryption vs an unencrypted implementation

Key config knob in libsrt: `SRTO_ENFORCEDENCRYPTION`, **default TRUE** on both
sides. All statements below are libsrt 1.4.4 behavior.

**A. Unencrypted listener receives CONCLUSION with KMREQ (caller has a passphrase):**

* Default (`ENFORCEDENCRYPTION=true`): reject the connection with
  **`SRT_REJ_UNSECURE` → Handshake Type `1011`** in the rejection response
  ("Peer declares encryption, but agent does not — rejecting per enforced
  encryption"). *This is what a from-scratch unencrypted implementation must do by
  default.*
* Non-enforced mode (both sides would need `ENFORCEDENCRYPTION=false`): accept the
  connection, respond with a CONCLUSION response whose Extension Field includes
  `0x2` and that carries a **KMRSP of length 1 word = `SRT_KM_S_NOSECRET` (3)**.
  The caller's data would arrive encrypted and undecryptable (must be dropped on
  receive: any data packet with header `KK != 0`), while data sent by the listener
  flows unencrypted. Not recommended; implement only if you need the permissive
  mode.

**B. Unencrypted caller connects to a listener that demands crypto (listener has a
passphrase, caller sends no KMREQ):**

* Default: the listener's post-check ("Agent declares encryption, but Peer does
  not") rejects; the caller receives a CONCLUSION-phase handshake with
  **Handshake Type `1011` (`SRT_REJ_UNSECURE`)** and must report "password required
  or unexpected" and stop retrying.
* If the listener is non-enforced: it accepts and its HSRSP side includes a KMRSP
  error block (`SRT_KM_S_NOSECRET`); an enforced caller (default) receiving a KMRSP
  error must itself abort with local reason `SRT_REJ_UNSECURE`; a non-enforced
  caller continues (listener→caller data will be encrypted garbage, dropped by KK
  check; caller→listener data flows unencrypted).

**C. Sanity rules for the unencrypted implementation:**

* Never send KMREQ; never set the `0x2` bit in Extension Field of the CONCLUSION
  request; always send Encryption Field = 0.
* Ignore the advertised PBKEYLEN in the induction response.
* If a CONCLUSION sets Extension Field bit `0x2` but contains no KM block, reject
  `SRT_REJ_ROGUE` (libsrt does).
* `SRT_KM_S_*` codes (KMRSP payload word): UNSECURED=0, SECURING=1, SECURED=2,
  NOSECRET=3, BADSECRET=4. On BADSECRET conditions libsrt rejects with
  `SRT_REJ_BADSECRET` (1010) under enforced encryption — an unencrypted
  implementation never generates this itself.

---

## 10. What srt-live-transmit 1.4.4 actually sends

`srt-live-transmit` uses the library defaults for everything protocol-visible
(verified in `apps/transmitmedia.cpp`): it sets only `SRTO_RCVSYN=false` (and
`SRTO_SNDSYN=false` on the output side — non-blocking; protocol-invisible),
leaves `SRTO_TSBPDMODE` at its default *true* (it only ever sets it to false when
the URI carries `tsbpd=false`), `SRTO_SENDER=true` (HSv4-only relevance;
**no effect** on the HSv5 wire) and
whatever the user puts in the URI query (`latency=`, `rcvlatency=`, `peerlatency=`,
`streamid=`, `passphrase=`, `pbkeylen=`, `mss=`, `fc=`, `conntimeo=`, …).

Concretely, an unmodified `srt://` caller URI without options produces:

* INDUCTION request: Version 4, Type word `0x00000002`, MTU 1500, Flow Window 8192,
  random ISN, cookie 0, dst-ID 0.
* CONCLUSION request: Version 5, Encryption Field 0, Extension Field `0x0001`
  (`0x0005` when `streamid=` is given; `0x0003`/`0x0007` with `passphrase=`),
  dst-ID 0, echoed cookie.
* HSREQ: SRT Version `0x010404`, Flags **`0x000000BF`**
  (TSBPDSND|TSBPDRCV|CRYPT|TLPKTDROP|PERIODICNAK|REXMITFLG|PACKET_FILTER; STREAM
  clear), Receiver TSBPD Delay = 120 (or `latency`/`rcvlatency` value), Sender
  TSBPD Delay = 0 (or `peerlatency` value).
* Extension order on the wire: HSREQ, then SID (if any), then KMREQ (if any) —
  never CONGESTION (live), never FILTER/GROUP.
* As a listener it responds with: INDUCTION response Version 5 / `0x4A17` /
  Encryption Field 0 (no passphrase), and a CONCLUSION response with Extension
  Field `0x0001`, HSRSP flags `0x000000BF`, latency fields per §4.2
  (120/120 with defaults), MTU 1500, Flow Window 8192, caller's ISN echoed.
* Data payload chunking (`SRTO_PAYLOADSIZE` default 1316) — not handshake-visible.

---

## 11. Summary of draft ↔ libsrt 1.4.4 differences (all resolved in libsrt's favor)

1. **Induction response CIF SRT Socket ID**: draft/handshake.md say listener's ID;
   libsrt echoes the caller's ID. Do not read this field; echo it as listener (§5.2).
2. **CONCLUSION request header Destination Socket ID**: draft says the socket ID
   from the induction phase; libsrt sends **0**, and its listener only accepts
   connection handshakes on ID 0 (§5.3).
3. **Missing `0x4A17` magic in induction response**: draft says reject; libsrt 1.4.4
   caller only logs a warning and proceeds (§5.2).
4. **Cookie in CONCLUSION response**: draft says sent "without the cookie"; libsrt
   echoes the caller's cookie. Field is ignored either way (§5.4).
5. **Peer IP Address semantics**: draft says "address of the packet's sender";
   libsrt writes the packet's *destination* (peer) address. Unvalidated either way
   (§2.2).
6. **Cookie tolerance**: draft says only "1 minute accuracy"; libsrt 1.4.4
   *intends* current-or-previous-minute but a sign error makes the fallback compute
   the (useless) next-minute cookie, so effectively only the current minute
   validates; fixed in later libsrt. This implementation accepts current and
   previous minute (§6).
7. **Rejection codes**: draft Table 7 stops at 1015 (`REJ_GROUP`); libsrt 1.4.4 adds
   `SRT_REJ_TIMEOUT` (1016, local only) and the ≥2000 extended ranges (§3.1).
8. Draft's Extension Field table is normative for CONCLUSION only; in INDUCTION the
   same 16 bits carry `2` (request) / `0x4A17` (response) (§2).

UNCONFIRMED items (not verifiable from the cited sources; flagged for testing):

* UNCONFIRMED: whether any deployed *non-1.4.4* SRT peer validates the induction
  request's Extension Field value `2` — 1.4.4 verifiably does not (its
  `processConnectRequest` induction branch never reads `m_iType`; the `UDT_DGRAM`
  check exists only in the HSv4 CONCLUSION path); older/other implementations were
  not audited. Send `2` regardless.

(Resolved since the first revision: the big-endian IPv4 Peer IP behavior is now
source-verified against v1.4.4 `common.cpp` — see §2.2 note; only runtime testing
on BE hardware remains undone, and it is irrelevant for LE interop targets.)
