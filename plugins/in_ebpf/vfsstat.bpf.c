/* This program is based on vfsstat.py on bcc repo and extended:
 *  https://github.com/iovisor/bcc/blob/master/tools/vfsstat.py
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "vfsstat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u64 stats[__FLB_S_MAXSTAT] = {};

static __always_inline int increment_stats(int key)
{
    __atomic_add_fetch(&stats[key], 1, __ATOMIC_RELAXED);
    return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe_vfs_read)
{
    return increment_stats(FLB_S_READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write)
{
    return increment_stats(FLB_S_WRITE);
}

SEC("kprobe/vfs_fsync")
int BPF_KPROBE(kprobe_vfs_fsync)
{
    return increment_stats(FLB_S_FSYNC);
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe_vfs_open)
{
    return increment_stats(FLB_S_OPEN);
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(kprobe_vfs_create)
{
    return increment_stats(FLB_S_CREATE);
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(kprobe_vfs_unlink)
{
    return increment_stats(FLB_S_UNLINK);
}

SEC("kprobe/vfs_truncate")
int BPF_KPROBE(kprobe_vfs_truncate)
{
    return increment_stats(FLB_S_TRUNCATE);
}

SEC("kprobe/vfs_fallocate")
int BPF_KPROBE(kprobe_vfs_fallocate)
{
    return increment_stats(FLB_S_FALLOCATE);
}
