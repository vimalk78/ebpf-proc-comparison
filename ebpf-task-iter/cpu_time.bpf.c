//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h> // For pid_t

// Define pid_t if not provided
#ifndef pid_t
typedef int pid_t;
#endif

// Define struct bpf_iter__task
struct bpf_iter__task {
    struct task_struct *task;
} __attribute__((preserve_access_index));

// Define necessary parts of struct task_struct
struct task_struct {
    pid_t tgid;                   // Thread group ID (process ID)
    unsigned long long utime;     // User CPU time
    unsigned long long stime;     // System CPU time
} __attribute__((preserve_access_index));

// BPF map to store CPU time per process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);             // Key: tgid (process ID)
    __type(value, unsigned long long); // Value: Total CPU time
} cpu_time_map SEC(".maps");


// BPF iterator program
SEC("iter/task")
int sum_cpu_time(struct bpf_iter__task *ctx)
{
    struct task_struct *task = ctx->task;
    if (task == NULL) {
        return 0; // Skip if no task
    }

    // Calculate total CPU time
    pid_t tgid = task->tgid;
    unsigned long long cpu_time = task->utime + task->stime;

    // Update the map
    unsigned long long *val = bpf_map_lookup_elem(&cpu_time_map, &tgid);
    if (val) {
        *val += cpu_time; // Update existing entry
    } else {
        bpf_map_update_elem(&cpu_time_map, &tgid, &cpu_time, BPF_NOEXIST); // Add new entry
    }

    return 0; // Continue iteration
}

// License section
char _license[] SEC("license") = "GPL";
