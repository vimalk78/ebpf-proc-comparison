package isolated

import (
	"maps"
	"slices"

	"github.com/vimalk78/ebpf-proc-hybrid/internal/ebpf"
	. "github.com/vimalk78/ebpf-proc-hybrid/internal/types"
)

type cpuTracker struct {
	// currentProcs is for the previous loop-interval
	currentProcs map[Pid]ebpf.ActiveProc

	// previousProcs is for the loop-interval prior to current
	previousProcs map[Pid]ebpf.ActiveProc
}

var (
	tracker = map[CPUId]cpuTracker{}
)

func Init(isolated []CPUId) {
	for _, cpu := range isolated {
		tracker[cpu] = cpuTracker{
			currentProcs:  map[Pid]ebpf.ActiveProc{},
			previousProcs: map[Pid]ebpf.ActiveProc{},
		}
	}
}

func Track(cpu CPUId, proc ebpf.ActiveProc) {
	t, _ := tracker[cpu]
	t.currentProcs[proc.Pid] = proc
}

func ActiveProcs(cpu CPUId) []ebpf.ActiveProc {
	t, ok := tracker[cpu]
	if ok {
		if t.currentProcs != nil && len(t.currentProcs) != 0 {
			// some activity happened on isolated cpu
			activeProcs := t.currentProcs
			// current becomes previous
			t.currentProcs, t.previousProcs = nil, t.currentProcs
			return slices.Collect(maps.Values(activeProcs))
		} else {
			// no activity happened on isolated cpu
			activeProcs := t.previousProcs
			// previous remains previous
			return slices.Collect(maps.Values(activeProcs))
		}
	}
	return []ebpf.ActiveProc{}
}
