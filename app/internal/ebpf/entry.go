package ebpf

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

func RunEbpfProg() error {
	var objs mysqlResponseTraceObjects
	if err := loadMysqlResponseTraceObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	// Attach kprobe to tcp_connect
	kp, err := link.Kprobe("tcp_sendmsg", objs.TcpSendmsg, nil)
	if err != nil {
		return err
	}
	defer kp.Close()
	slog.Info("✅ eBPF program loaded and attached to tcp_sendmsg")
	slog.Info("Press Ctrl+C to exit...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Exiting...")

	return nil
}
