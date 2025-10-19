ARCH := x86
BINARY := mysql-response-trace
BUILD_DIR := ./bin
APP_DIR := ./app
GOSRC     := ./$(APP_DIR)/cmd ./$(APP_DIR)/internal ./$(APP_DIR)/*.go

# eBPF C programs (relative to project root)
BPF_DIR   := ./$(APP_DIR)/bpf
BPF_C     := ./$(APP_DIR)/$(wildcard $(BPF_DIR)/*.c)

# Go related variables
GO      ?= go
GOFLAGS :=
LDFLAGS := -s -w

.PHONY: all build run clean bpf-gen

# Default target
all: build

# Generate eBPF Go code via go:generate
bpf-gen-btf:
	@echo ">> generate vmlinux.h using bpftool"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./$(APP_DIR)/bpf/vmlinux.h

bpf-gen:
	@echo ">> Generating eBPF Go code using go:generate"
	@$(GO) generate ./app


# Build the Go binary
build: bpf-gen
	@echo ">> Building $(BINARY)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./app

# Run the binary
run: build
	@echo ">> Running $(BINARY)"
	$(BUILD_DIR)/$(BINARY)

# Clean generated files
clean:
	rm -f bpf_$(ARCH)_*.o bpf_$(PROG)_*.go
	rm -rf $(BINARY)

# Build docker
docker-build:
	docker build -t $(ARGS) .

docker-push:
	docker push $(ARGS)