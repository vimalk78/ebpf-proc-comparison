//go:build ignore

#include <stddef.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct task_struct {
	int pid;
	unsigned int tgid;
} __attribute__((preserve_access_index));

/* Structure for active PID information */
struct active_proc {
    __u32 pid; // pid in userspace, but tgid in kernel space
    int cpu;
    char comm[16];
};

/* BPF map of active PIDs with minimal info */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct active_proc);
} active_procs SEC(".maps");

static inline void do_update(__u32 pid, __u32 tgid)
{
    // Skip kernel threads (pid == 0)
    if (pid == 0)
        return;
    
    // Prepare minimal process info
    struct active_proc info = {0};
    
    // Get CPU ID and timestamp
    info.pid = tgid;
    info.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    //if (__builtin_memcmp(&info.comm, "swapper/", 8) == 0){
    //  return;
    //}
    if (__builtin_memcmp(&info.comm, "kworker", 7) == 0){
	return;
    }
    
    // Update active PIDs map
    bpf_map_update_elem(&active_procs, &tgid, &info, BPF_NOEXIST);
}

/* BTF-enabled tracepoint for sched_switch */
SEC("tp_btf/sched_switch")
int handle_sched_switch(__u64 *ctx)
{
    struct task_struct *prev_task;
    prev_task = (struct task_struct *)ctx[1];
    __u32 prev_pid = prev_task->pid;
    __u32 prev_tgid = prev_task->tgid;
    do_update(prev_pid, prev_tgid);

    struct task_struct *next_task;
    next_task = (struct task_struct *)ctx[2];
    __u32 next_pid = next_task->pid;
    __u32 next_tgid = next_task->tgid;
    do_update(next_pid, next_tgid);

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
