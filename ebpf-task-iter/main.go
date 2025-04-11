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

// ProcessData holds information about a process
type ProcessData struct {
	PID        uint32
	CPUTime    uint64
	LastTime   uint64
	Comm       string
	Executable string
}

// ProcessUsage represents CPU usage for a process
type ProcessUsage struct {
	PID        uint32
	CPUDelta   float64 // Delta in seconds
	TotalTime  float64 // Total time in seconds
	Comm       string
	Executable string
}

// Config holds the application configuration
type Config struct {
	interval time.Duration
	count    int
	clkTck   int64
}

func main() {
	// Parse command line flags
	cfg := parseFlags()

	// Set up correct rlimit for eBPF operations
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock: %v", err)
	}

	// Load and set up BPF program
	objs, it, err := setupBPF()
	if err != nil {
		log.Fatalf("Failed to setup BPF: %v", err)
	}
	defer cleanup(objs, it)

	// Get system clock tick rate
	cfg.clkTck, err = sysconf.Sysconf(sysconf.SC_CLK_TCK)
	if err != nil {
		log.Fatalf("Error getting CLK_TCK: %v", err)
	}

	// Start monitoring
	monitor(objs, it, cfg)
}

// parseFlags parses command line flags and returns a Config
func parseFlags() Config {
	interval := flag.Duration("interval", 1*time.Second, "Reporting interval (e.g. 1s, 500ms)")
	count := flag.Int("count", 0, "Number of top processes to show (0 for all)")
	flag.Parse()

	return Config{
		interval: *interval,
		count:    *count,
	}
}

// setupBPF loads and attaches the BPF program
func setupBPF() (*cpuTimeObjects, *link.Iter, error) {
	// Load the pre-compiled BPF program
	objs := cpuTimeObjects{}
	if err := loadCpuTimeObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load BPF objects: %v", err)
	}

	// Attach the iterator
	it, err := link.AttachIter(link.IterOptions{
		Program: objs.SumCpuTime,
	})
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("failed to attach BPF iterator: %v", err)
	}

	return &objs, it, nil
}

// cleanup handles proper resource cleanup
func cleanup(objs *cpuTimeObjects, it *link.Iter) {
	if it != nil {
		it.Close()
	}
	if objs != nil {
		objs.Close()
	}
}

// monitor starts the main monitoring loop
func monitor(objs *cpuTimeObjects, it *link.Iter, cfg Config) {
	// Store previous CPU times to calculate deltas
	processData := make(map[uint32]ProcessData)

	// Set up signal handling for clean shutdown
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Timer to trigger periodic reporting
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	fmt.Printf("Monitoring CPU usage at %s intervals... Press Ctrl+C to exit\n", cfg.interval)

	// Initial collection to establish baseline
	if err := collectAndPrintCPUData(objs, it, processData, cfg); err != nil {
		log.Printf("Initial collection error: %v", err)
	}

	// Main loop
	for {
		select {
		case <-ticker.C:
			if err := collectAndPrintCPUData(objs, it, processData, cfg); err != nil {
				log.Printf("Error collecting CPU data: %v", err)
			}
		case <-stopper:
			fmt.Println("\nShutting down...")
			return
		}
	}
}

// collectAndPrintCPUData collects and displays CPU usage data
func collectAndPrintCPUData(objs *cpuTimeObjects, it *link.Iter, processData map[uint32]ProcessData, cfg Config) error {
	startedAt := time.Now()
	currentData, keys, err := collectCurrentData(it, objs)
	if err != nil {
		return err
	}

	// Delete all keys in a batch
	if _, err := objs.ProcessMap.BatchDelete(keys, nil); err != nil {
		return fmt.Errorf("failed to batch delete keys: %v", err)
	}

	// Calculate usage data with deltas
	usageData := calculateUsageData(currentData, processData, cfg.clkTck)

	// Update stored data for next iteration
	updateStoredData(processData, currentData)

	// Sort and print results
	printResults(usageData, cfg.count, startedAt)

	return nil
}

// collectCurrentData runs the iterator and collects current process data
func collectCurrentData(it *link.Iter, objs *cpuTimeObjects) (map[uint32]ProcessData, []uint32, error) {
	// Open iterator to run the iterator
	iter, err := it.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open iterator: %v", err)
	}
	defer iter.Close()

	// Read to run the iterator (no output expected)
	buf := make([]byte, 1)
	_, err = iter.Read(buf)
	if err != nil && !errors.Is(err, os.ErrClosed) && err.Error() != "EOF" {
		return nil, nil, fmt.Errorf("error reading from iterator: %v", err)
	}

	// Collect current CPU times
	currentData := make(map[uint32]ProcessData)
	var key uint32
	var value cpuTimeProcessInfo
	var keys []uint32

	cpuIter := objs.ProcessMap.Iterate()
	for cpuIter.Next(&key, &value) {
		keys = append(keys, key)

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
		return nil, nil, fmt.Errorf("error iterating map: %v", err)
	}

	return currentData, keys, nil
}

// calculateUsageData calculates CPU usage with deltas
func calculateUsageData(currentData, processData map[uint32]ProcessData, clkTck int64) []ProcessUsage {
	var usageData []ProcessUsage

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
	}

	// Sort by CPU delta (descending)
	sort.Slice(usageData, func(i, j int) bool {
		return usageData[i].CPUDelta > usageData[j].CPUDelta
	})

	return usageData
}

// updateStoredData updates the process data map for the next iteration
func updateStoredData(processData map[uint32]ProcessData, currentData map[uint32]ProcessData) {
	for pid, current := range currentData {
		processData[pid] = ProcessData{
			PID:        pid,
			CPUTime:    current.CPUTime,
			LastTime:   current.CPUTime,
			Comm:       current.Comm,
			Executable: current.Executable,
		}
	}
}

// printResults displays the CPU usage results
func printResults(usageData []ProcessUsage, count int, startedAt time.Time) {
	limit := len(usageData)
	if count > 0 {
		limit = min(limit, count)
	}

	fmt.Printf("\nCPU Usage (at %s):\n", startedAt.Format("15:04:05"))
	fmt.Println("-----------------------------------------------------------------------------------------------")
	fmt.Printf("%-7s %-15s %-15s %-20s %-30s\n", "PID", "CPU (last int)", "Total CPU Time", "Command", "Executable")
	for _, process := range usageData[:limit] {
		// Only show processes with non-zero CPU usage in this interval
		// if process.CPUDelta > 0 {
		fmt.Printf("%-7d %-15.2fs %-15.2fs %-20s %-30s\n",
			process.PID,
			process.CPUDelta,
			process.TotalTime,
			truncateString(process.Comm, 20),
			truncateString(process.Executable, 30))
		//}
	}

	duration := time.Since(startedAt)
	fmt.Printf("----->>>------------------------- %d: %v ---------- <<< ------------\n", len(usageData), duration)
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
