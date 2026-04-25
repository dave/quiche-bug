# Reproducer server: Cloudflare quiche's tokio-quiche async_http3_server
# example, running with kernel-level outbound packet reordering.
#
# Build with stock quiche:
#   docker build -t quiche-bug-server:stock .
#
# Build with the .max(2) patch applied:
#   docker build --build-arg APPLY_PATCH=1 -t quiche-bug-server:patched .

FROM rust:1.88-slim AS builder
ARG QUICHE_REF=master
ARG APPLY_PATCH=0

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    perl \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# quiche's BoringSSL bindings drag in C++ symbols that the Rust
# linker doesn't pull automatically.
ENV RUSTFLAGS="-Clink-arg=-lstdc++"

WORKDIR /build
RUN git clone --recursive https://github.com/cloudflare/quiche.git && \
    cd quiche && git checkout $QUICHE_REF && \
    git submodule update --init --recursive

COPY pkt_num_len.patch /tmp/pkt_num_len.patch
RUN if [ "$APPLY_PATCH" = "1" ]; then \
      echo "[build] applying pkt_num_len.patch"; \
      cd /build/quiche && git apply /tmp/pkt_num_len.patch; \
    else \
      echo "[build] stock quiche (no patch)"; \
    fi

RUN cd /build/quiche && \
    cargo build --release -p tokio-quiche --example async_http3_server

# Self-signed cert at build time so the binary boots cleanly.
RUN apt-get update && apt-get install -y --no-install-recommends openssl && \
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /tmp/key.pem -out /tmp/cert.pem -days 365 \
      -subj "/CN=quiche-bug-reproducer"


FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/quiche/target/release/examples/async_http3_server /usr/local/bin/async_http3_server
COPY --from=builder /tmp/cert.pem /etc/quiche/cert.pem
COPY --from=builder /tmp/key.pem /etc/quiche/key.pem

# tokio-quiche's example clap config eagerly canonicalizes its
# default cert path (CARGO_MANIFEST_DIR/examples/cert.{crt,key})
# even when --tls-cert-path is supplied. Stage stub files so
# canonicalize() doesn't panic at startup.
RUN mkdir -p /build/quiche/tokio-quiche/examples
COPY --from=builder /tmp/cert.pem /build/quiche/tokio-quiche/examples/cert.crt
COPY --from=builder /tmp/key.pem /build/quiche/tokio-quiche/examples/cert.key

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 4443/udp
ENTRYPOINT ["/entrypoint.sh"]
