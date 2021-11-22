/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tcpconnect.h"
#include "maps.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct sock *);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv4_flow_key_t);
    __type(value, u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv6_flow_key_t);
    __type(value, u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_counts SEC(".maps");

static __always_inline int
enter_connect(struct pt_regs *ctx, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid;

    bpf_map_update_elem(&sockets, &tid, &sk, 0);
    return 0;
}

static  __always_inline void count_v4_connection(struct sock *sk, __u16 dest_port)
{
    struct ipv4_flow_key_t key = {};
    static __u64 zero;
    __u64 *val;

    BPF_CORE_READ_INTO(&key.saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&key.daddr, sk, __sk_common.skc_daddr);
    key.dport = dest_port;
    val = bpf_map_lookup_or_try_init(&ipv4_counts, &key, &zero);
    if (val)
        __atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void count_v6_connection(struct sock *sk, __u16 dest_port)
{
    struct ipv6_flow_key_t key = {};
    static const __u64 zero;
    __u64 *val;

    BPF_CORE_READ_INTO(&key.saddr, sk,
               __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&key.daddr, sk,
               __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    key.dport = dest_port;

    val = bpf_map_lookup_or_try_init(&ipv6_counts, &key, &zero);
    if (val)
        __atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline int
exit_connect(struct pt_regs *ctx, int ret, int ip_version)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    struct sock **pp_sk;
    struct sock *sk;
    __u16 dest_port;

    pp_sk = bpf_map_lookup_elem(&sockets, &tid);
    if (pp_sk == NULL) {
        return 0;
    }

    if (ret) {
        goto cleanup;
    }

    sk = *pp_sk;

    BPF_CORE_READ_INTO(&dest_port, sk, __sk_common.skc_dport);

    switch (ip_version) {
    case 4:
        count_v4_connection(sk, dest_port);
        break;
    case 6:
        count_v6_connection(sk, dest_port);
        break;
    default:
        ;;
    }

cleanup:
    bpf_map_delete_elem(&sockets, &tid);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk)
{
    return enter_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe_tcp_v4_connect, int ret)
{
    return exit_connect(ctx, ret, 4);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock *sk)
{
    return enter_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kretprobe_tcp_v6_connect, int ret)
{
    return exit_connect(ctx, ret, 6);
}
