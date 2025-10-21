# =========================================
# 1️⃣ Build stage — compile eBPF + Go binary
# =========================================
FROM golang:1.25-bookworm AS builder

# Install clang, llvm, bpftool (for bpf2go to work)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev bpftool make \
    && rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy go.mod and download deps first (cache layer)
COPY Makefile ./
COPY ./app ./app
RUN go work init ./app
RUN go mod download

# Copy all source code
RUN make


# =========================================
# 2️⃣ Runtime stage — minimal container
# =========================================
FROM debian:bookworm-slim

# Needed for kernel interaction and debugging
RUN apt-get update && apt-get install -y --no-install-recommends bpftool iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/bin/mysql-error-echo .

# eBPF programs require privileged mode & access to /sys
CMD ["./mysql-error-echo"]
