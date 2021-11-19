#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/oom.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define FLB_OOMKILL_MAX_ENTRIES 64

struct oom_mark_victim {
  __u64 padding;
  int pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, int);
    __type(value, __u8);
    __uint(max_entries, FLB_OOMKILL_MAX_ENTRIES);
} oomkill SEC(".maps");

SEC("tracepoint/oom/mark_victim")
int handle_oom_mark_victim(struct oom_mark_victim *entry) {
    int pid = entry->pid;
    __u8 val = 0;
    bpf_map_update_elem(&oomkill, &pid, &val, BPF_ANY);
    return 0;
}
