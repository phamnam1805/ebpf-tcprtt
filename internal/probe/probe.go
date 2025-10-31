package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"ebpf-tcprtt/internal/hist"
	"time"
)

//go:generate env GOPACKAGE=probe go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/tcprtt.bpf.c -- -O2

const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2
const fortyMegaBytes = twentyMegaBytes * 2

type probe struct {
	bpfObjects *probeObjects
	tcpRcvLink link.Link
}

func setRlimit() error {
	log.Println("Setting rlimit")

	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: twentyMegaBytes,
		Max: fortyMegaBytes,
	})
}

func setUnlimitedRlimit() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Failed setting infinite rlimit: %v", err)
		return err
	}
	return nil
}

func htons(hostOrder uint16) uint16 {
	return (hostOrder << 8) | (hostOrder >> 8)
}

func htonl(hostOrder uint32) uint32 {
	return ((hostOrder & 0xFF) << 24) |
		(((hostOrder >> 8) & 0xFF) << 16) |
		(((hostOrder >> 16) & 0xFF) << 8) |
		((hostOrder >> 24) & 0xFF)
}

func ntohl(netOrder uint32) uint32 {
	return ((netOrder & 0xFF) << 24) |
		(((netOrder >> 8) & 0xFF) << 16) |
		(((netOrder >> 16) & 0xFF) << 8) |
		((netOrder >> 24) & 0xFF)
}

// Receive net order
func parseIPv4(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

func newProbe(laddrHist bool, raddrHist bool, showExt bool, sport int, dport int, saddr uint32, daddr uint32, ms bool) (*probe, error) {
	log.Println("Creating a new probe")

	prbe := probe{}

	if err := prbe.loadObjects(laddrHist, raddrHist, showExt, sport, dport, saddr, daddr, ms); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.attachPrograms(); err != nil {
		log.Printf("Failed attaching ebpf programs: %v", err)
		return nil, err
	}

	return &prbe, nil
}

func (p *probe) loadObjects(laddrHist bool, raddrHist bool, showExt bool, sport int, dport int, saddr uint32, daddr uint32, ms bool) error {
	log.Printf("Loading probe object into kernel")

	objs := probeObjects{}

	spec, err := loadProbe()
	if err != nil {
		return err
	}

	if laddrHist {
		if err := spec.Variables["targ_laddr_hist"].Set(uint8(1)); err != nil {
			log.Printf("Failed setting targ_laddr_hist: %v", err)
			return err
		}

		log.Printf("Set targ_laddr_hist to %t", laddrHist)
	}

	if raddrHist {
		if err := spec.Variables["targ_raddr_hist"].Set(uint8(1)); err != nil {
			log.Printf("Failed setting targ_raddr_hist: %v", err)
			return err
		}

		log.Printf("Set targ_raddr_hist to %t", raddrHist)
	}

	if showExt {
		if err := spec.Variables["targ_show_ext"].Set(uint8(1)); err != nil {
			log.Printf("Failed setting targ_show_ext: %v", err)
			return err
		}

		log.Printf("Set targ_show_ext to %t", showExt)
	}

	if sport > 0 {
		if err := spec.Variables["targ_sport"].Set(htons(uint16(sport))); err != nil {
			log.Printf("Failed setting targ_sport: %v", err)
			return err
		}

		log.Printf("Set targ_sport to %d", sport)
	}

	if dport > 0 {
		if err := spec.Variables["targ_dport"].Set(htons(uint16(dport))); err != nil {
			log.Printf("Failed setting targ_dport: %v", err)
			return err
		}

		log.Printf("Set targ_dport to %d", dport)
	}

	if saddr > 0 {
		if err := spec.Variables["targ_saddr"].Set(ntohl(saddr)); err != nil {
			log.Printf("Failed setting targ_saddr: %v", err)
			return err
		}

		log.Printf("Set targ_saddr to %d", ntohl(saddr))
	}

	if daddr > 0 {
		if err := spec.Variables["targ_daddr"].Set(ntohl(daddr)); err != nil {
			log.Printf("Failed setting targ_daddr: %v", err)
			return err
		}

		log.Printf("Set targ_daddr to %d", ntohl(daddr))
	}

	if ms {
		if err := spec.Variables["targ_ms"].Set(uint8(1)); err != nil {
			log.Printf("Failed setting targ_ms: %v", err)
			return err
		}

		log.Printf("Set targ_ms to %t", ms)
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) attachPrograms() error {
	log.Printf("Attaching bpf programs to kernel")

	tcpRcvLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.bpfObjects.TcpRcv,
	})
	if err != nil {
		log.Printf("Failed to link tracepoint fentry/tcp_rcv_established: %v", err)
		return err
	}
	p.tcpRcvLink = tcpRcvLink
	log.Printf("Successfully linked tracepoint fentry/tcp_rcv_established")
	return nil
}

func (p *probe) Close() error {
	log.Println("Closing eBPF object")

	if p.tcpRcvLink != nil {
		p.tcpRcvLink.Close()
	}

	return nil
}

func Run(ctx context.Context, laddrHist bool, raddrHist bool, showExt bool, sport int, dport int, saddr uint32, daddr uint32, ms bool) error {
	log.Println("Starting up the probe")

	if err := setUnlimitedRlimit(); err != nil {
		log.Printf("Failed setting rlimit: %v", err)
		return err
	}

	probe, err := newProbe(laddrHist, raddrHist, showExt, sport, dport, saddr, daddr, ms)
	if err != nil {
		log.Printf("Failed creating new probe: %v", err)
		return err
	}

	histsMap := probe.bpfObjects.probeMaps.Hists
	defer histsMap.Close()

	go func() {
		for {
			fmt.Println("=== Reading map entries ===")
			iter := histsMap.Iterate()

			var key uint64
			var val hist.Hist

			for iter.Next(&key, &val) {

				if key > 0 {
					fmt.Printf("Key: %s\n", parseIPv4(htonl(uint32(key))))
				} else {
					fmt.Printf("Key: %d\n", (uint32(key))) // key is in the host order
				}

				val.PrintInfo()
			}
			if err := iter.Err(); err != nil {
				log.Printf("Iterator error: %v", err)
			}

			fmt.Println("===========================")
			time.Sleep(10 * time.Second)
		}
	}()

	<-ctx.Done()
	return probe.Close()
}
