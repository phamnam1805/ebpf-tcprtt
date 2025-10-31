// ...existing code...
package main

import (
    "context"
    "flag"
    "log"
    "os"
    "os/signal"
    "syscall"
	"net"
	"fmt"

    "ebpf-tcprtt/internal/probe"
)

var (
    laddrHist = flag.Bool("laddr-hist", false, "group histogram by local address")
    raddrHist = flag.Bool("raddr-hist", false, "group histogram by remote address")
    showExt   = flag.Bool("show-ext", false, "collect extended stats (latency/cnt)")
    sport     = flag.Int("sport", 0, "source port filter")
    dport     = flag.Int("dport", 0, "destination port filter")
    saddrStr  = flag.String("saddr", "", "source IPv4 address filter (as dotted string, e.g. 192.168.1.1)")
    daddrStr  = flag.String("daddr", "", "destination IPv4 address filter (as dotted string, e.g. 192.168.1.1)")
    ms        = flag.Bool("ms", false, "report srtt in milliseconds")
)

func signalHandler(cancel context.CancelFunc) {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigChan
        log.Println("\nCaught SIGINT... Exiting")
        cancel()
    }()
}

// Return net order
func parseIPv4ToBe32(ipStr string) (uint32, error) {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return 0, fmt.Errorf("invalid IP address: %s", ipStr)
    }
    
    ipv4 := ip.To4()
    if ipv4 == nil {
        return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
    }
    
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), nil
}

func main() {
    flag.Parse()

    ctx := context.Background()
    ctx, cancel := context.WithCancel(ctx)

    signalHandler(cancel)

	saddr := uint32(0)
	daddr := uint32(0)
    var err error
    if *saddrStr != "" {
        saddr, err = parseIPv4ToBe32(*saddrStr)
        if err != nil {
            log.Fatalf("Invalid source address: %v", err)
        }
    }
    if *daddrStr != "" {
        daddr, err = parseIPv4ToBe32(*daddrStr)
        if err != nil {
            log.Fatalf("Invalid destination address: %v", err)
        }
    }
    if err := probe.Run(ctx,
        *laddrHist,
        *raddrHist,
        *showExt,
        *sport,
        *dport,
        saddr,
        daddr,
        *ms,
    ); err != nil {
        log.Fatalf("Failed running the probe: %v", err)
    }
}