#!/bin/sh
# Entrypoint for the quiche reproducer server.
#
# Applies kernel-level outbound packet reordering on the default
# interface, then starts tokio-quiche's example HTTP/3 server.
#
# The reorder qdisc is what creates the >128-packet decode-ambiguity
# window that triggers the pkt_num_len bug — without it, the
# packets arrive in order and the receiver always reconstructs the
# correct full packet number.
set -e

LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0:4443}"

# Reorder outbound packets — every 200th packet skips the 200ms
# delay, jumping ahead of the in-flight delayed packets. With 50%
# probability of skipping, the effective reorder distance is ~200
# packets, comfortably past the 128 safe threshold for 1-byte pn
# truncation.
IF=$(ip route | awk '/default/ {print $5; exit}')
echo "[entrypoint] applying netem on $IF: delay 200ms reorder 50% gap 200"
tc qdisc add dev "$IF" root netem delay 200ms reorder 50% gap 200 \
  || echo "[entrypoint] tc failed (need NET_ADMIN cap); continuing without reorder"

echo "[entrypoint] launching async_http3_server on $LISTEN_ADDR"
exec /usr/local/bin/async_http3_server \
  --address "$LISTEN_ADDR" \
  --tls-cert-path /etc/quiche/cert.pem \
  --tls-private-key-path /etc/quiche/key.pem
