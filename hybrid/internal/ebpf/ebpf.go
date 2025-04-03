package ebpf

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type ActiveProcPids = []uint32

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

func (bm *bpfManager) GetActiveProcPids() (ActiveProcPids, error) {
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
	return keys[:total], nil
}

func (bm *bpfManager) Close() {
	bm.bpfObjs.Close()
	if bm.tracePoint != nil {
		bm.tracePoint.Close()
	}
}
