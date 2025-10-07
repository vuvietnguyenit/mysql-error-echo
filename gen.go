package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir ./internal/ebpf -go-package ebpf -output-suffix _gobpf -tags linux mysqlTrace ./bpf/trace.bpf.c
