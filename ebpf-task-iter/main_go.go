package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/tklauser/go-sysconf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" cpuTime ./cpu_time.bpf.c

func main() {
	// Set up correct rlimit for eBPF operations
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock: %v", err)
	}

	// Load the pre-compiled BPF program
	objs := cpuTimeObjects{}
	if err := loadCpuTimeObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Attach the iterator
	it, err := link.AttachIter(link.IterOptions{
		Program: objs.SumCpuTime,
	})
	if err != nil {
		log.Fatalf("Failed to attach BPF iterator: %v", err)
	}
	defer it.Close()

	// Open iterator
	iter, err := it.Open()
	if err != nil {
		log.Fatalf("Failed to open iterator: %v", err)
	}
	defer iter.Close()

	// Read to run the iterator (no output expected)
	buf := make([]byte, 1)
	_, err = iter.Read(buf)
	if err != nil && !errors.Is(err, os.ErrClosed) && err.Error() != "EOF" {
		log.Fatalf("Error reading from iterator: %v", err)
	}

	// Get clock tick rate for converting jiffies to seconds
	clkTck, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	if err != nil {
		log.Fatalf("Error getting CLK_TCK: %v", err)
	}

	// Set up signal handling for clean shutdown
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Monitoring CPU usage... Press Ctrl+C to exit")
	<-stopper

	// Print the final results
	var key uint32
	var value uint64

	fmt.Println("\nCPU Usage by Process:")
	fmt.Println("---------------------")

	cpuIter := objs.CpuTimeMap.Iterate()
	for cpuIter.Next(&key, &value) {
		cpuTimeSeconds := float64(value) / float64(clkTck)
		fmt.Printf("PID %d: %.2f seconds\n", key, cpuTimeSeconds)
	}

	if err := cpuIter.Err(); err != nil {
		log.Fatalf("Error iterating map: %v", err)
	}
}
