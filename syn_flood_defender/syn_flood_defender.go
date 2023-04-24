package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf syn_flood_defender.c -- -Iheaders
func main() {
	log := logrus.New()

	// Look up the network interface by name.
	ifaceName := "lo"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Infof("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.XdpBannedIpsMap)
		if err != nil {
			log.Infof("Error banning too fast syn hosts: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key uint32
		val uint64
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := net.IPv4(byte(key>>24), byte(key>>16), byte(key>>8), byte(key)).String()
		sb.WriteString(fmt.Sprintf("%s ", sourceIP))
	}
	return sb.String(), iter.Err()
}
