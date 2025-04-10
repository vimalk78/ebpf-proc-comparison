package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/tklauser/go-sysconf"
)

// Must match the C struct process_info from the BPF program
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" cpuTime ./cpu_time.bpf.c
// type cpuTimeProcessInfo struct {
// 	CpuTime uint64
// 	Comm    [16]byte
// }

// ProcessData holds information about a process
type ProcessData struct {
	PID        uint32
	CPUTime    uint64
	LastTime   uint64
	Comm       string
	Executable string
}

func main() {
	// Parse command line flags
	interval := flag.Duration("interval", 1*time.Second, "Reporting interval (e.g. 1s, 500ms)")
	count := flag.Int("count", 0, "Number of top processes to show (0 for all)")
	flag.Parse()

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

	// Get clock tick rate for converting jiffies to seconds
	clkTck, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	if err != nil {
		log.Fatalf("Error getting CLK_TCK: %v", err)
	}

	// Store previous CPU times to calculate deltas
	processData := make(map[uint32]ProcessData)

	// Set up signal handling for clean shutdown
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Timer to trigger periodic reporting
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	fmt.Printf("Monitoring CPU usage at %s intervals... Press Ctrl+C to exit\n", interval)

	// Function to collect and print CPU data
	collectAndPrintCPUData := func() error {
		// Open iterator to run the iterator
		iter, err := it.Open()
		if err != nil {
			return fmt.Errorf("failed to open iterator: %v", err)
		}
		defer iter.Close()

		// Read to run the iterator (no output expected)
		buf := make([]byte, 1)
		_, err = iter.Read(buf)
		if err != nil && !errors.Is(err, os.ErrClosed) && err.Error() != "EOF" {
			return fmt.Errorf("error reading from iterator: %v", err)
		}

		// Collect current CPU times
		var key uint32
		var value cpuTimeProcessInfo
		currentData := make(map[uint32]ProcessData)

		cpuIter := objs.ProcessMap.Iterate()
		for cpuIter.Next(&key, &value) {
			// Get executable path from /proc
			executable := getExecutablePath(key)

			// Convert command name from [16]byte to string, trimming NUL bytes
			comm := trimNullBytes(value.Comm[:])

			currentData[key] = ProcessData{
				PID:        key,
				CPUTime:    value.CpuTime,
				Comm:       comm,
				Executable: executable,
			}
		}
		if err := cpuIter.Err(); err != nil {
			return fmt.Errorf("error iterating map: %v", err)
		}

		// Calculate deltas and update stored data
		type ProcessUsage struct {
			PID        uint32
			CPUDelta   float64 // Delta in seconds
			TotalTime  float64 // Total time in seconds
			Comm       string
			Executable string
		}

		var usageData []ProcessUsage
		startedAt := time.Now()

		for pid, current := range currentData {
			usage := ProcessUsage{
				PID:        pid,
				TotalTime:  float64(current.CPUTime) / float64(clkTck),
				Comm:       current.Comm,
				Executable: current.Executable,
			}

			// Calculate delta if we have previous data
			if prev, exists := processData[pid]; exists {
				cpuDelta := current.CPUTime - prev.LastTime
				usage.CPUDelta = float64(cpuDelta) / float64(clkTck)
			}

			usageData = append(usageData, usage)

			// Update stored data
			processData[pid] = ProcessData{
				PID:        pid,
				CPUTime:    current.CPUTime,
				LastTime:   current.CPUTime,
				Comm:       current.Comm,
				Executable: current.Executable,
			}
		}

		// Clear the map for next iteration
		if err := objs.ProcessMap.Delete(nil); err != nil {
			log.Printf("Warning: failed to clear process map: %v", err)
		}

		// Sort by CPU delta (descending)
		sort.Slice(usageData, func(i, j int) bool {
			return usageData[i].CPUDelta > usageData[j].CPUDelta
		})

		// Print the results
		fmt.Printf("\nCPU Usage (at %s):\n", startedAt.Format("15:04:05"))
		fmt.Println("-----------------------------------------------------------------------------------------------")
		fmt.Printf("%-7s %-15s %-15s %-20s %-30s\n", "PID", "CPU (last int)", "Total CPU Time", "Command", "Executable")

		limit := len(usageData)
		if *count > 0 && *count < limit {
			limit = *count
		}

		for i := 0; i < limit; i++ {
			process := usageData[i]
			// Only show processes with non-zero CPU usage in this interval
			if process.CPUDelta > 0 {
				fmt.Printf("%-7d %-15.2fs %-15.2fs %-20s %-30s\n",
					process.PID,
					process.CPUDelta,
					process.TotalTime,
					truncateString(process.Comm, 20),
					truncateString(process.Executable, 30))
			}
		}

		duration := time.Since(startedAt)
		fmt.Printf("-------------------------------------------------------------------- %v ----------------------\n", duration)

		return nil
	}

	// Initial collection to establish baseline
	if err := collectAndPrintCPUData(); err != nil {
		log.Printf("Initial collection error: %v", err)
	}

	// Main loop
	for {
		select {
		case <-ticker.C:
			if err := collectAndPrintCPUData(); err != nil {
				log.Printf("Error collecting CPU data: %v", err)
			}
		case <-stopper:
			fmt.Println("\nShutting down...")
			return
		}
	}
}

// getExecutablePath returns the path to the executable of a process
func getExecutablePath(pid uint32) string {
	path := fmt.Sprintf("/proc/%d/exe", pid)
	exe, err := os.Readlink(path)
	if err != nil {
		// Return empty string if we can't read the executable path
		// This could happen for system processes or if we don't have permissions
		return ""
	}
	return exe
}

// truncateString truncates a string to the given length and adds "..." if it was truncated
func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

// trimNullBytes removes null bytes from the end of a byte slice and returns as string
func trimNullBytes(b []int8) string {
	sb := strings.Builder{}

	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}
