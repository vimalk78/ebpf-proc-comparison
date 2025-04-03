package ebpf

import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type ActiveProcs []struct {
	Pid  uint32
	Comm string
}

type bpfManager struct {
	bpfObjs    keplerObjects
	tracePoint link.Link
}

var (
	instance *bpfManager
	once     sync.Once
	initErr  error
)

func Instance() (*bpfManager, error) {
	once.Do(func() {
		instance, initErr = nil, nil
		bpfObjs := keplerObjects{}
		if err := loadKeplerObjects(&bpfObjs, nil); err != nil {
			initErr = fmt.Errorf("Failed to load BPF objects: %v", err)
			return
		}

		// Attach the eBPF program to BTF-enabled tracepoint
		tp, err := link.AttachTracing(link.TracingOptions{
			Program:    bpfObjs.HandleSchedSwitch,
			AttachType: ebpf.AttachTraceRawTp,
		})
		if err != nil {
			initErr = fmt.Errorf("Failed to attach BTF tracepoint: %v", err)
			return
		}
		instance = &bpfManager{
			bpfObjs:    bpfObjs,
			tracePoint: tp,
		}
	})
	return instance, initErr
}

func MustInstance() *bpfManager {
	mgr, err := Instance()
	if err != nil {
		panic("failed to initialize bpf " + err.Error())
	}
	return mgr
}

func (bm *bpfManager) GetActiveProcs() (ActiveProcs, error) {
	activeProcsMap := bm.bpfObjs.ActiveProcs
	maxEntries := activeProcsMap.MaxEntries()
	total := 0
	keys := make([]uint32, maxEntries)
	values := make([]keplerActiveProc, maxEntries)
	var cursor ebpf.MapBatchCursor
	for {
		count, err := activeProcsMap.BatchLookupAndDelete(
			&cursor,
			keys,
			values,
			&ebpf.BatchOptions{},
		)
		total += count
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	procs := make(ActiveProcs, total)
	for i, proc := range values[:total] {
		procs[i].Pid = proc.Pid
		procs[i].Comm = C.GoString((*C.char)(unsafe.Pointer(&proc.Comm)))
	}
	return procs, nil
}

func (bm *bpfManager) Close() {
	bm.bpfObjs.Close()
	if bm.tracePoint != nil {
		bm.tracePoint.Close()
	}
}
