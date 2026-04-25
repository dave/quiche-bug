# quiche `pkt_num_len` 1-byte truncation reproducer

This repo reproduces an AEAD-decryption-failure bug in
[Cloudflare quiche](https://github.com/cloudflare/quiche).

`quiche/src/packet.rs::pkt_num_len` will choose a 1-byte truncated
packet number when fewer than 128 packets are unacked. RFC 9000
permits this, but it is unsafe: if the receiver observes more than
128 packets reordered, the entire valid range collapses and the
decoded full packet number lands on the wrong candidate. The AEAD
nonce is derived from the full packet number, so the receiver
fails to decrypt an otherwise-good packet.

The reference Go implementation, [quic-go](https://github.com/quic-go/quic-go),
explicitly refuses 1-byte truncation for this exact reason. From
[`internal/protocol/packet_number.go`](https://github.com/quic-go/quic-go/blob/master/internal/protocol/packet_number.go#L41-L42):

> // ... it never chooses a `PacketNumberLen` of 1 byte, since this is
> // too short under certain circumstances ...

When a quic-go client (a quic-go-based mobile app, in the original
field report) talks to quiche over a path that occasionally
reorders >128 packets, the bug manifests as `payload_decrypt_error`
events in qlog and request stalls in the application.

## Repository layout

```
.
├── server/                       Docker image: tokio-quiche async_http3_server
│   ├── Dockerfile                builds with --build-arg APPLY_PATCH={0,1}
│   ├── entrypoint.sh             applies tc/netem reorder, launches server
│   └── pkt_num_len.patch         the proposed fix (see Fix section)
├── client/                       Go reproducer client
│   ├── main.go                   uses quic-go HTTP/3, scans qlog for AEAD errors
│   ├── go.mod
│   └── go.sum
├── docker-compose.yml            convenience: `docker compose up server-stock`
└── README.md
```

## Quickstart

You need:
* Docker (with `NET_ADMIN` capability — required so the server can install
  a `tc/netem` qdisc on its container interface)
* Go 1.21+ (for the client)
* Linux host. The server image runs the netem qdisc inside the
  container; this works fine on Linux Docker. macOS Docker Desktop
  uses a Linux VM internally, so it works there too.

### 1. Run the unpatched server

```sh
docker build --build-arg APPLY_PATCH=0 -t quiche-bug-server:stock ./server
docker run --rm --cap-add=NET_ADMIN -p 4443:4443/udp quiche-bug-server:stock
```

The container will:
1. Apply `tc qdisc ... netem delay 200ms reorder 50% gap 200` to its
   default interface. This is what creates a >128-packet reorder
   window (see *Why these settings* below).
2. Launch `tokio-quiche/examples/async_http3_server` listening on
   `0.0.0.0:4443/udp`.

### 2. Run the client

```sh
cd client
go run . --url=https://localhost:4443 --duration=90s
```

Sample output against **stock quiche**:

```
qlog dir: qlog
starting 8 workers against https://localhost:4443 for 1m30s
t+30s sent=227 completed=219 failed=0
t+60s sent=521 completed=513 failed=0
t+90s sent=788 completed=780 failed=0
done after 1m30s — sent=788 completed=780 failed=0
qlog 762f78168dccc3bbbfff_client.sqlog: 6 payload_decrypt_error events
=== AEAD failure total: 6 ===
FAIL — server emitted packet numbers that the client could not decode
       (this is the quiche pkt_num_len 1-byte truncation bug)
```

Note: `failed=0` (the requests all eventually complete) but the
qlog shows 6 packets the client couldn't decrypt. Each AEAD failure
corresponds to a packet quic-go correctly identified as
"unrecoverable" because the truncated packet number was ambiguous.
quic-go retransmits, the request eventually completes, but the
connection has demonstrated the protocol-level bug.

### 3. Run the patched server

```sh
docker build --build-arg APPLY_PATCH=1 -t quiche-bug-server:patched ./server
docker run --rm --cap-add=NET_ADMIN -p 4443:4443/udp quiche-bug-server:patched

# in another terminal
cd client
go run . --url=https://localhost:4443 --duration=90s
```

Sample output against **patched quiche**:

```
done after 1m30s — sent=836 completed=828 failed=0
=== AEAD failure total: 0 ===
PASS — no AEAD decryption errors observed
```

Same exact server behaviour, same network conditions, same client.
The only difference is `pkt_num_len` no longer returns 1 byte.

## Why these settings

The bug fires only when the receiver observes >128 packets reordered
*and* the sender used a 1-byte truncated packet number for some of
those packets. The two conditions are in tension because quiche
only emits 1-byte PNs when fewer than 128 packets are unacked.

The `delay 200ms reorder 50% gap 200` qdisc creates a steady
condition where every 200th packet jumps ahead of ~199 delayed
packets. With the steady cadence of an HTTP/3 stream, most packets
fly under 2-byte PNs, but at boundaries (when an ACK clears a large
batch and the unacked count drops below 128) the next outgoing
packet is emitted with a 1-byte PN — and that packet, plus any
adjacent ones, is now in the reorder window. The client receives
them out of order, and the 1-byte truncation no longer
unambiguously decodes.

In production, this same condition arises naturally any time a
real network path produces a >128-packet reorder window — common
on mobile data networks, VPN egress points with batch processing,
and anywhere QUIC packet pacing meets aggregator hardware.

## Fix

The patch applied with `APPLY_PATCH=1` is at
[`server/pkt_num_len.patch`](server/pkt_num_len.patch). It is
two lines of code: floor the result of `pkt_num_len` at 2 bytes.

```diff
 pub fn pkt_num_len(pn: u64, largest_acked: u64) -> usize {
     let num_unacked: u64 = pn.saturating_sub(largest_acked) + 1;
     // computes ceil of num_unacked.log2() + 1
     let min_bits = u64::BITS - num_unacked.leading_zeros() + 1;
-    // get the num len in bytes
-    min_bits.div_ceil(8) as usize
+    // get the num len in bytes; floor at 2 to avoid the 1-byte
+    // truncation ambiguity that breaks AEAD decryption when the
+    // receiver sees more than 128 packets reordered.
+    (min_bits.div_ceil(8) as usize).max(2)
 }
```

Cost: 1 byte per outgoing 1-RTT packet for the small fraction of
packets where `num_unacked < 128`. quic-go has accepted this cost
for years.

## Background

This bug was originally observed in production at
[Viatrail](https://viatrail.app), an outdoor hiking app that uses
HTTP/3 to fetch map tiles from Cloudflare R2. Mobile users on
4G/5G saw 5-30 second stalls at unpredictable intervals; qlog
captures showed `payload_decrypt_error` events firing in clusters,
with the decoded packet number consistently off from the actual
packet number by exactly 256 (or 256·*k*) — the precise signature
of 1-byte truncation ambiguity.

After verifying that quic-go specifically refuses to emit such
packet numbers, and that quiche willingly does so, this reproducer
was built to demonstrate the bug end-to-end with no production
data path involved.
