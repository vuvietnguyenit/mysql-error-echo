ARCH := x86
BINARY := mysql-connection-trace
BUILD_DIR := ./bin
GOSRC     := ./cmd ./internal ./*.go

# eBPF C programs (relative to project root)
BPF_DIR   := ./bpf
BPF_C     := $(wildcard $(BPF_DIR)/*.c)

# Go related variables
GO      ?= go
GOFLAGS :=
LDFLAGS := -s -w

.PHONY: all build run clean bpf-gen

# Default target
all: build

# Generate eBPF Go code via go:generate
bpf-gen:
	@echo ">> Generating eBPF Go code using go:generate"
	@$(GO) generate .

# Build the Go binary
build: bpf-gen
	@echo ">> Building $(BINARY)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) .

# Run the binary
run: build
	@echo ">> Running $(BINARY)"
	$(BUILD_DIR)/$(BINARY)

# Clean generated files
clean:
	rm -f bpf_$(ARCH)_*.o bpf_$(PROG)_*.go
	rm -rf $(BINARY)