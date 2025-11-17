FROM golang:1.25.4-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o mysql-error-echo .

FROM debian:bookworm-slim
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     libpcap0.8 tcpdump wget curl netcat-traditional net-tools\
#     && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/mysql-error-echo .
ENTRYPOINT ["./mysql-error-echo"]
