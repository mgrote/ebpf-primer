package packetcount

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"ebpf-primer/log"
)

func PacketCount(networkInterfaceName string) error {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Logger.V(2).WithName("ebpf-packetcount").Error(err, "Removing memlock")
		return fmt.Errorf("remove memlock: %w", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Logger.V(2).WithName("ebpf-packetcount").Error(err, "Loading eBPF objects:")
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(networkInterfaceName)
	if err != nil {
		log.Logger.V(2).WithName("ebpf-packetcount").Error(err, "Get interface:", "network interface", networkInterfaceName)
		return fmt.Errorf("get interface %s: %w", networkInterfaceName, err)
	}

	// Attach count_packets to the network interface.
	attachXDP, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Logger.V(2).WithName("ebpf-packetcount").Error(err, "Attaching XDP")
		return fmt.Errorf("attach XDP: %w", err)
	}
	defer attachXDP.Close()

	log.Logger.V(2).WithName("ebpf-packetcount").Info("Counting incoming packets", "network interface", networkInterfaceName)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				return fmt.Errorf("map lookup: %w", err)
			}
			log.Logger.V(2).WithName("ebpf-packetcount").Info("Received packets", "count", count)
		case <-stop:
			log.Logger.V(2).WithName("ebpf-packetcount").Info("Received signal, exiting..")
			return nil
		}
	}
}
