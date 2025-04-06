package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"strings"

	"github.com/google/go-cmp/cmp"
)

func Test_readPidProcStatFromStr(t *testing.T) {
	tests := []struct {
		name    string
		pid     uint32
		stats   string
		utime   CpuTicks
		stime   CpuTicks
		comm    string
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got2, got3, gotErr := readPidProcStatFromStr(tt.pid, strings.TrimSpace(tt.stats))
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("readPidProcStatFromStr() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("readPidProcStatFromStr() succeeded unexpectedly")
			}
			if true {
				t.Errorf("readPidProcStatFromStr() got: %v, want: %v", got, tt.utime)
			}
			if true {
				t.Errorf("readPidProcStatFromStr() got: %v, want: %v", got2, tt.stime)
			}
			if true {
				t.Errorf("readPidProcStatFromStr() got: %v, want: %v", got3, tt.comm)
			}
		})
	}
}

func Test_readCpuProcStatFromStr(t *testing.T) {
	tests := []struct {
		name    string
		numCpu  int
		kind    int
		data    string
		want    []CpuTicks
		wantErr bool
	}{
		{
			name:   "overall cpu",
			numCpu: 0,
			kind:   User | System,
			data: `
                  cpu 100 0 300 0 0 0 0 0 0 0`,
			want: []CpuTicks{400},
		},
		{
			name:   "overall cpu and cpu 1",
			numCpu: 1,
			kind:   User | System,
			data: `
                  cpu  100 0 300 0 0 0 0 0 0 0
                  cpu0 110 0 310 0 0 0 0 0 0 0
			`,
			want: []CpuTicks{400, 420},
		},
		{
			name:   "overall cpu and cpu 1, User + Nice + System",
			numCpu: 1,
			kind:   User | Nice | System,
			data: `
                  cpu  100 200 300 0 0 0 0 0 0 0
                  cpu0 110 210 310 0 0 0 0 0 0 0
			`,
			want: []CpuTicks{600, 630},
		},
		{
			name:    "overall cpu and cpu 1",
			numCpu:  1,
			kind:    User | System,
			data:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := readCpuProcStatFromStr(tt.numCpu, tt.kind, strings.TrimSpace(tt.data))
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("readCpuProcStatFromStr() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("readCpuProcStatFromStr() succeeded unexpectedly")
			}
			if !cmp.Equal(got, tt.want) {
				t.Errorf(
					"readCpuProcStatFromStr() got: %v, want: %v, diff: %v",
					got,
					tt.want,
					cmp.Diff(got, tt.want),
				)
			}
		})
	}
}

func Test_getIsolatedCPUsFromStr(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    []int
		wantErr bool
	}{
		{
			name: "no isolated cpus",
			data: "",
			want: []int{},
		},
		{
			name: "simple comma separated",
			data: "1,2",
			want: []int{1, 2},
		},
		{
			name: "isolated single range with two cpus",
			data: "2-3",
			want: []int{2, 3},
		},
		{
			name: "isolated single range with multiple cpus",
			data: "2-5",
			want: []int{2, 3, 4, 5},
		},
		{
			name: "isolated multiple ranges",
			data: "2-3,12-15",
			want: []int{2, 3, 12, 13, 14, 15},
		},
		{
			name:    "non number range",
			data:    "2-o",
			wantErr: true,
		},
		{
			name:    "invalid range",
			data:    "2-3-4",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := getIsolatedCPUsFromStr(strings.TrimSpace(tt.data))
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getIsolatedCPUsFromStr() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getIsolatedCPUsFromStr() succeeded unexpectedly")
			}
			if !cmp.Equal(got, tt.want) {
				t.Errorf(
					"getIsolatedCPUsFromStr() got: %v, want: %v, diff: %v",
					got,
					tt.want,
					cmp.Diff(got, tt.want),
				)
			}
		})
	}
}

func Test_getProcPidsFromDir(t *testing.T) {
	tempDir := t.TempDir()
	fmt.Printf("tempDir: %s\n", tempDir)
	pids := []uint32{34, 88, 987987, 98786576}
	for _, pid := range pids {
		_, err := os.Create(filepath.Join(tempDir, fmt.Sprintf("%d", pid)))
		if err != nil {
			t.Errorf("could not create file in temDir")
		}
	}
	nonPids := []string{"cpuinfo", "meminfo"}
	for _, f := range nonPids {
		_, err := os.Create(filepath.Join(tempDir, f))
		if err != nil {
			t.Errorf("could not create file in temDir")
		}
	}
	got, gotErr := getProcPidsFromDir(tempDir)
	if gotErr != nil {
		t.Errorf("getProcPidsFromDir() failed: %v", gotErr)
	}
	slices.Sort(got)
	slices.Sort(pids)
	if !cmp.Equal(got, pids) {
		t.Errorf(
			"getProcPidsFromDir() got: %v, want: %v, diff: %v",
			got,
			pids,
			cmp.Diff(got, pids),
		)
	}
}
