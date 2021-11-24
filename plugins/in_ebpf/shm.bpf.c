/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"
#include "flb_ebpf_helper.h"
#include "shm.h"

#define MAX_ENTRIES 0x8000 /* FIXME: Determine this value at compile time*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct flb_shm_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} pid_shms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, __FLB_SHM_SYSCALL_END);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} shm_counts SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline int increment_shm_stats(int key)
{
    __u64 start = 1;
    __u64 *val;

    val = bpf_map_lookup_elem(&shm_counts, &key);
    if (val) {
        flb__update_u64(val, 1);
    } else {
        bpf_map_update_elem(&shm_counts, &key, &start, BPF_ANY);
    }

    return 0;
}

#if defined __TARGET_x86_64
SEC("kprobe/__x64_sys_shmget")
#else
SEC("kprobe/sys_shmget")
#endif
int BPF_KPROBE(kprobe_shmget)
{
    struct flb_shm_t shm = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 key = pid_tgid >> 32;
    struct flb_shm_t *filled = bpf_map_lookup_elem(&pid_shms, &key);

    increment_shm_stats(FLB_SHM_GET_SYSCALL);

    if (filled) {
        flb__update_u64(&filled->get, 1);
    }
    else {
        shm.get = 1;
        bpf_map_update_elem(&pid_shms, &key, &shm, BPF_ANY);
    }

    return 0;
}

#if defined __TARGET_x86_64
SEC("kprobe/__x64_sys_shmat")
#else
SEC("kprobe/sys_shmat")
#endif
int BPF_KPROBE(kprobe_shmat)
{
    struct flb_shm_t shm = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 key = pid_tgid >> 32;
    struct flb_shm_t *filled = bpf_map_lookup_elem(&pid_shms, &key);

    increment_shm_stats(FLB_SHM_AT_SYSCALL);

    if (filled) {
        flb__update_u64(&filled->at, 1);
    }
    else {
        shm.at = 1;
        bpf_map_update_elem(&pid_shms, &key, &shm, BPF_ANY);
    }

    return 0;
}

#if defined __TARGET_x86_64
SEC("kprobe/__x64_sys_shmdt")
#else
SEC("kprobe/sys_shmdt")
#endif
int BPF_KPROBE(kprobe_shmdt)
{
    struct flb_shm_t shm = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 key = pid_tgid >> 32;
    struct flb_shm_t *filled = bpf_map_lookup_elem(&pid_shms, &key);

    increment_shm_stats(FLB_SHM_DT_SYSCALL);

    if (filled) {
        flb__update_u64(&filled->dt, 1);
    }
    else {
        shm.dt = 1;
        bpf_map_update_elem(&pid_shms, &key, &shm, BPF_ANY);
    }

    return 0;
}

#if defined __TARGET_x86_64
SEC("kprobe/__x64_sys_shmctl")
#else
SEC("kprobe/sys_shmctl")
#endif
int BPF_KPROBE(kprobe_shmctl)
{
    struct flb_shm_t shm = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 key = pid_tgid >> 32;

    struct flb_shm_t *filled = bpf_map_lookup_elem(&pid_shms, &key);

    increment_shm_stats(FLB_SHM_CTL_SYSCALL);

    if (filled) {
        flb__update_u64(&filled->ctl, 1);
    }
    else {
        shm.ctl = 1;
        bpf_map_update_elem(&pid_shms, &key, &shm, BPF_ANY);
    }

    return 0;
}
