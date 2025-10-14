package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir ./internal/ebpf -go-package ebpf -output-suffix _gobpf -tags linux mysqlResponseTrace ./bpf/mysql_response_trace.c -- -I./headers -D__TARGET_ARCH_x86
