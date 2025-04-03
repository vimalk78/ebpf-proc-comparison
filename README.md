## allproc
A program which reads all procssses in /proc, and prints the number of procs and the time cost of reading the /proc/<pid>/stat for all the procs
## hybrid
A program which uses ebpf to get all the active processes and reads /proc for those processes only, and prints the number of active procs and time cost of reading /proc/<pid>/stat for the active procs
## comparison
- comparison-video.mp4 : shows a sample run for both programs
- ebpf-overhead.md: shows the ebpf overhead in the hybrid approach
- pprof flame graph screenshot for both
