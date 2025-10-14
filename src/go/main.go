package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	objs := struct {
		Prog *ebpf.Program `ebpf:"handle_execve"`
	}{}

	// Load compiled program
	spec, err := ebpf.LoadCollectionSpec("../bpf/program.o")
	if err != nil {
		log.Fatalf("loading collection spec: %v", err)
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Prog.Close()

	// Attach to tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.Prog, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("eBPF program loaded and attached. Press Ctrl+C to exit.")

	// Wait until user stops
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Exiting...")
}
