//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h> // For pid_t

// Define pid_t if not provided
#ifndef pid_t
typedef int pid_t;
#endif

// Define TASK_COMM_LEN if not provided
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
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
    char comm[TASK_COMM_LEN];     // Command name
} __attribute__((preserve_access_index));

// Data structure to store process information
struct process_info {
    unsigned long long cpu_time;   // Total CPU time
    char comm[TASK_COMM_LEN];      // Command name
};

// BPF map to store process information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);            // Key: tgid (process ID)
    __type(value, struct process_info); // Value: Process information
} process_map SEC(".maps");

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
    struct process_info *info = bpf_map_lookup_elem(&process_map, &tgid);
    if (info) {
        // Update existing entry
        info->cpu_time += cpu_time;
    } else {
        // Create new entry
        struct process_info new_info = {
            .cpu_time = cpu_time
        };
        
        // Copy the command name
        __builtin_memcpy(new_info.comm, task->comm, TASK_COMM_LEN);
        
        bpf_map_update_elem(&process_map, &tgid, &new_info, BPF_NOEXIST);
    }

    return 0; // Continue iteration
}

// License section
char _license[] SEC("license") = "GPL";
