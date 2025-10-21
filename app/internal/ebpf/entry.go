package ebpf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	appflag "git.itim.vn/docker/mysql-response-trace/app/flag"
	"git.itim.vn/docker/mysql-response-trace/app/internal/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type dataT struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Size  uint32
	Msg   [512]byte
}

func (d *dataT) GetMsg() string {
	// Trim the null bytes from the message
	s := bytes.Trim(d.Msg[:], "\x00")
	s = bytes.ReplaceAll(s, []byte{0x00}, []byte{})
	return string(s)
}
func (d *dataT) String() string {
	if !utils.IsMySQLErrorMessage(d.Msg[:]) {
		return ""
	}
	return fmt.Sprintf(
		"[%s] respone: %s:%d -> %s:%d | size=%d | msg=%s",
		time.Now().Format(time.RFC3339),
		utils.IntToIP(d.Saddr),
		d.Sport,
		utils.IntToIP(d.Daddr),
		d.Dport,
		d.Size,
		d.GetMsg(),
	)
}

func RunEbpfProg() error {
	var objs mysqlResponseTraceObjects
	if err := loadMysqlResponseTraceObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	key := uint32(0)
	configMap := objs.ConfigMap
	if err := configMap.Update(&key, appflag.Port, ebpf.UpdateAny); err != nil {
		return err
	}
	slog.Debug("set port filter", slog.Any("port", appflag.Port))

	// Attach kprobe to tcp_connect
	kp, err := link.Kprobe("tcp_sendmsg", objs.TcpSendmsg, nil)
	if err != nil {
		return err
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		slog.Error("failed to open ringbuf reader", slog.Any("err", err))
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			slog.Error("closing ringbuf reader: %s", slog.Any("err", err))
		}
	}()

	slog.Info("eBPF program loaded and attached to tcp_sendmsg")
	slog.Info("Press Ctrl+C to exit...")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return err
			}
			continue
		}

		var e dataT
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			slog.Error("binary read failed", slog.Any("err", err))
			continue
		}

		if appflag.Verbose {
			data := make([]byte, e.Size)
			buf := bytes.NewReader(record.RawSample)
			binary.Read(buf, binary.LittleEndian, &e)
			buf.Read(data)
			fmt.Printf("%s:%d -> %s:%d: size=%d\n", utils.IntToIP(e.Saddr), e.Sport, utils.IntToIP(e.Daddr), e.Dport, e.Size)
			fmt.Println("HEX DUMP:")
			fmt.Printf("%s\n\n", hex.Dump(e.Msg[:]))
		}
		if e.String() != "" {
			fmt.Println(e.String())
		}
	}
}
