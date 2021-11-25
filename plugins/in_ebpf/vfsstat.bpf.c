/* This program is based on vfsstat.py on bcc repo and extended:
 *  https://github.com/iovisor/bcc/blob/master/tools/vfsstat.py
 */
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "flb_ebpf_helper.h"
#include "vfsstat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, __FLB_S_MAXSTAT);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} vfs_counts SEC(".maps");

__u64 stats[__FLB_S_MAXSTAT] = {};

static __always_inline int increment_stats(int key)
{
    __u64 start = 1;
    __u64 *val;

    val = bpf_map_lookup_elem(&vfs_counts, &key);
    if (val) {
        flb__update_u64(val, 1);
    } else {
        bpf_map_update_elem(&vfs_counts, &key, &start, BPF_ANY);
    }

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
