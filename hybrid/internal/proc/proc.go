package proc

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type CpuTicks = uint64

type CpuTicksKind = int

const (
	User      CpuTicksKind = 1 << iota //	Time spent in user mode (normal processes)
	Nice                               //	Time spent in user mode with low priority (nice)
	System                             //	Time spent in kernel mode (system calls, interrupts)
	Idle                               //	Time spent in the idle task (waiting for I/O, no work)
	IOWait                             //	Time spent waiting for I/O to complete
	Irq                                //	Time servicing hardware interrupts
	Softirq                            //	Time servicing software interrupts
	Steal                              //	Time stolen by the hypervisor for other VMs (only in VMs)
	Guest                              //	Time spent running a guest OS in user mode (VMs)
	GuestNice                          //	Time spent running a guest OS with a nice value

	// most commonly used
	UserSystem     = User | System
	UserNiceSystem = User | Nice | System
)

// Read /proc/<pid>/stat
func ReadPidProcStat(pid uint32) (CpuTicks, CpuTicks, string, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statBytes, err := os.ReadFile(statPath)
	if err != nil {
		return 0, 0, "", fmt.Errorf("failed to read %s: %w", statPath, err)
	}
	return readPidProcStatFromStr(pid, string(statBytes))
}

// Parse the stat file content
func readPidProcStatFromStr(pid uint32, stats string) (CpuTicks, CpuTicks, string, error) {
	// Handle processes with parentheses in names
	// Format: pid (comm) state ppid ...
	commStart := strings.IndexByte(stats, '(')
	commEnd := strings.LastIndexByte(stats, ')')

	if commStart == -1 || commEnd == -1 || commEnd < commStart {
		return 0, 0, "", fmt.Errorf("invalid stat format for pid %d", pid)
	}

	// Extract fields after the command name
	fields := strings.Fields(stats[commEnd+1:])

	// Fields 14 and 15 in the original file are utime and stime
	// But they're at index 12 and 13 after splitting the trailing part
	if len(fields) < 14 {
		return 0, 0, "", fmt.Errorf("not enough fields in stat for pid %d", pid)
	}

	// Parse utime and stime
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, 0, "", fmt.Errorf("failed to parse utime: %w", err)
	}

	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, 0, "", fmt.Errorf("failed to parse stime: %w", err)
	}

	return CpuTicks(utime), CpuTicks(stime), stats[commStart+1 : commEnd], nil
}

/*
ReadCpuStat returns
*/
func ReadCpuStat(numCpu int, kind CpuTicksKind) ([]CpuTicks, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/stat: %v", err)
	}
	return readCpuProcStatFromStr(numCpu, kind, string(data))
}

func readCpuProcStatFromStr(numCpu int, kind CpuTicksKind, data string) ([]CpuTicks, error) {
	// we need to parse only first numCpu+1 lines
	lines := strings.SplitN(data, "\n", numCpu+1)
	if len(lines) < numCpu+1 {
		return nil, fmt.Errorf("not enough lines: %d", len(lines))
	}
	cpuTicks := make([]CpuTicks, numCpu+1) // +1 because first entry is for all cpus

	for i, line := range lines {
		if i > 0 && i == numCpu-1 {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			return nil, fmt.Errorf("invalid line %s", line)
		}
		var total CpuTicks
		for i, val := range fields[1:] {
			mask := 1 << i
			if kind&mask != 0 {
				tick, err := strconv.ParseUint(val, 10, 64)
				if err != nil {
					return []CpuTicks{0}, fmt.Errorf("invalid tick value: %v", err)
				}
				total += CpuTicks(tick)
			}
		}
		cpuTicks[i] = total
	}
	return cpuTicks, nil
}

func GetProcPids() ([]uint32, error) {
	return getProcPidsFromDir("/proc")
}

func getProcPidsFromDir(dir string) ([]uint32, error) {
	de, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read /proc dir %v", err)
	}
	count := 0
	pids := make([]uint32, len(de))
	for _, d := range de {
		if pid, err := strconv.ParseUint(d.Name(), 10, 32); err != nil {
			// could be some file/directory which is not a pid. like /proc/cpuinfo
			if errors.Is(err, strconv.ErrSyntax) {
				continue
			} else {
				return nil, err
			}
		} else {
			pids[count] = uint32(pid)
			count += 1
		}

	}
	return pids[:count], nil
}

func MustGetIsolatedCPUs() []int {
	cpus, err := GetIsolatedCPUs()
	if err != nil {
		panic("cannot get isolated cpus " + err.Error())
	}
	return cpus
}

func GetIsolatedCPUs() ([]int, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/isolated")
	if err != nil {
		return nil, fmt.Errorf("failed to read isolated CPUs: %v", err)
	}
	cpuStr := strings.TrimSpace(string(data))
	return getIsolatedCPUsFromStr(cpuStr)
}

func getIsolatedCPUsFromStr(cpuStr string) ([]int, error) {
	if cpuStr == "" {
		return []int{}, nil // No isolated CPUs
	}

	parts := strings.Split(cpuStr, ",")
	var cpus []int
	for _, part := range parts {
		cpuRange := strings.SplitN(part, "-", 2)
		if len(cpuRange) == 0 {
			continue
		} else if len(cpuRange) == 2 {
			cpuBegin, err := strconv.Atoi(cpuRange[0])
			if err != nil {
				return nil, fmt.Errorf("invalid range %s", part)
			}
			cpuEnd, err := strconv.Atoi(cpuRange[1])
			if err != nil {
				return nil, fmt.Errorf("invalid range %s", part)
			}
			if cpuBegin >= cpuEnd {
				return nil, fmt.Errorf("invalid range %s", part)
			}
			cpu := cpuBegin
			for cpu <= cpuEnd {
				cpus = append(cpus, cpu)
				cpu++
			}
		} else if len(cpuRange) == 1 {
			cpu, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid cpu %s", part)
			}
			cpus = append(cpus, cpu)
		}
	}
	return cpus, nil
}
