# syntax=docker/dockerfile:1

# =============================================================================
# STAGE 1: Rust builder — compiles the ingestor to a static binary
# =============================================================================
FROM rust:1.78-slim AS rust-builder

WORKDIR /build

# Cache dependencies before copying source
COPY ingest/rust-ingestor/Cargo.toml ingest/rust-ingestor/Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true

# Build actual source
COPY ingest/rust-ingestor/src ./src
RUN touch src/main.rs && cargo build --release

# =============================================================================
# STAGE 2: Python inference + dashboard runtime
# =============================================================================
FROM python:3.11-slim AS python-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# =============================================================================
# STAGE 3: Final ingestor image (tiny — just the Rust binary + pcap data)
# =============================================================================
FROM debian:bookworm-slim AS ingestor
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=rust-builder /build/target/release/rust-ingestor /usr/local/bin/rust-ingestor
COPY data/ /app/data/
WORKDIR /app
ENTRYPOINT ["rust-ingestor"]

# =============================================================================
# STAGE 4: Inference worker image
# =============================================================================
FROM python-base AS inference
CMD ["python", "-m", "inference.worker"]

# =============================================================================
# STAGE 5: Dashboard API image
# =============================================================================
FROM python-base AS dashboard
EXPOSE 8000
CMD ["uvicorn", "dashboard.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
