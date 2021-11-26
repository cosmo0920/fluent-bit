/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <msgpack.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include "vfsstat.skel.h"
#include "vfsstat.h"
#include "oom_victim.skel.h"
#include "tcpconnect.skel.h"
#include "tcpconnect.h"
#include "shm.skel.h"
#include "shm.h"
#include "ebpf.h"

static int print_libbpf_log(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) {
        return 0;
    }
    return vfprintf(stderr, fmt, args);
}

static int prepare_vsstat_ebpf(struct flb_in_ebpf *ctx)
{
    struct vfsstat_bpf *skel;
    int err;

    /* Open BPF application */
    skel = vfsstat_bpf__open();
    if (!skel) {
        flb_plg_error(ctx->ins, "Failed to open BPF skeleton");
        return 1;
    }

    /* Load & verify BPF programs */
    err = vfsstat_bpf__load(skel);
    if (err) {
        flb_plg_error(ctx->ins, "Failed to load and verify BPF skeleton");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = vfsstat_bpf__attach(skel);
    if (err) {
        flb_plg_error(ctx->ins, "Failed to attach BPF skeleton");
        goto cleanup;
    }

    flb_plg_info(ctx->ins, "Successfully eBPF vsstat started!");

    ctx->vfsstat_skel = skel;

    /* Prepare CMetrics metric */
    ctx->vfs_read = cmt_counter_create(ctx->cmt, "ebpf", "vfs", "read",
                                       "The number of calls for vfs read syscall", 0, NULL);
    if (ctx->vfs_read == NULL) {
        return -1;
    }

    ctx->vfs_write = cmt_counter_create(ctx->cmt, "ebpf", "vfs", "write",
                                       "The number of calls for vfs write syscall", 0, NULL);
    if (ctx->vfs_write == NULL) {
        return -1;
    }

    ctx->vfs_fsync = cmt_counter_create(ctx->cmt, "ebpf", "vfs", "fsync",
                                       "The number of calls for vfs fsync syscall", 0, NULL);
    if (ctx->vfs_fsync == NULL) {
        return -1;
    }

    ctx->vfs_open = cmt_counter_create(ctx->cmt, "ebpf", "vfs", "open",
                                       "The number of calls for vfs open syscall", 0, NULL);
    if (ctx->vfs_open == NULL) {
        return -1;
    }

    ctx->vfs_create = cmt_counter_create(ctx->cmt, "ebpf", "vfs", "create",
                                         "The number of calls for vfs create syscall", 0, NULL);
    if (ctx->vfs_create == NULL) {
        return -1;
    }

    ctx->vfs_unlink = cmt_counter_create(ctx->cmt, "ebpf", "vfs", "unlink",
                                         "The number of calls for vfs unlink syscall", 0, NULL);
    if (ctx->vfs_unlink == NULL) {
        return -1;
    }

    ctx->vfs_truncate = cmt_counter_create(ctx->cmt, "ebpf", "vfs", "truncate",
                                           "The number of calls for vfs truncate syscall", 0, NULL);
    if (ctx->vfs_unlink == NULL) {
        return -1;
    }

    ctx->vfs_fallocate = cmt_counter_create(ctx->cmt, "ebpf", "vfs", "fallocate",
                                            "The number of calls for vfs fallocate syscall", 0, NULL);
    if (ctx->vfs_fallocate == NULL) {
        return -1;
    }

    return 0;

cleanup:
    vfsstat_bpf__destroy(skel);
    ctx->vfsstat_skel = NULL;

    return -1;
}

static int prepare_oom_victim_ebpf(struct flb_in_ebpf *ctx)
{
    struct oom_victim_bpf *skel;
    int err;

    /* Open BPF application */
    skel = oom_victim_bpf__open();
    if (!skel) {
        flb_plg_error(ctx->ins, "Failed to open BPF skeleton");
        return 1;
    }

    /* Load & verify BPF programs */
    err = oom_victim_bpf__load(skel);
    if (err) {
        flb_plg_error(ctx->ins, "Failed to load and verify BPF skeleton");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = oom_victim_bpf__attach(skel);
    if (err) {
        flb_plg_error(ctx->ins, "Failed to attach BPF skeleton");
        goto cleanup;
    }

    flb_plg_info(ctx->ins, "Successfully eBPF oom_victim started!");

    ctx->oom_victim_skel = skel;

    /* Prepare CMetrics metric */
    ctx->oom_victim = cmt_counter_create(ctx->cmt, "ebpf", "oom", "victims",
                                         "The number of OOM victim processes", 0, NULL);
    if (ctx->oom_victim == NULL) {
        return -1;
    }

    return 0;

cleanup:
    oom_victim_bpf__destroy(skel);
    ctx->oom_victim_skel = NULL;

    return -1;
}

static int prepare_tcpconnect_ebpf(struct flb_in_ebpf *ctx)
{
    struct tcpconnect_bpf *skel;
    int err;

    /* Open BPF application */
    skel = tcpconnect_bpf__open();
    if (!skel) {
        flb_plg_error(ctx->ins, "Failed to open BPF skeleton");
        return 1;
    }

    /* Load & verify BPF programs */
    err = tcpconnect_bpf__load(skel);
    if (err) {
        flb_plg_error(ctx->ins, "Failed to load and verify BPF skeleton");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = tcpconnect_bpf__attach(skel);
    if (err) {
        flb_plg_error(ctx->ins, "Failed to attach BPF skeleton");
        goto cleanup;
    }

    flb_plg_info(ctx->ins, "Successfully eBPF tcpconnect started!");

    ctx->tcpconnect_skel = skel;

    /* Prepare CMetrics metric */
    ctx->ipv4_tcpconnect = cmt_gauge_create(ctx->cmt, "ebpf", "tcp", "ipv4 connections",
                                            "The number of IPv4 TCP connections", 0, NULL);
    if (ctx->ipv4_tcpconnect == NULL) {
        return -1;
    }

    ctx->ipv6_tcpconnect = cmt_gauge_create(ctx->cmt, "ebpf", "tcp", "ipv6 connections",
                                            "The number of IPv6 TCP connections", 0, NULL);
    if (ctx->ipv6_tcpconnect == NULL) {
        return -1;
    }

    return 0;

cleanup:
    tcpconnect_bpf__destroy(skel);
    ctx->tcpconnect_skel = NULL;

    return -1;
}

static int prepare_shm_ebpf(struct flb_in_ebpf *ctx)
{
    struct shm_bpf *skel;
    int err;

    /* Open BPF application */
    skel = shm_bpf__open();
    if (!skel) {
        flb_plg_error(ctx->ins, "Failed to open BPF skeleton");
        return 1;
    }

    /* Load & verify BPF programs */
    err = shm_bpf__load(skel);
    if (err) {
        flb_plg_error(ctx->ins, "Failed to load and verify BPF skeleton");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = shm_bpf__attach(skel);
    if (err) {
        flb_plg_error(ctx->ins, "Failed to attach BPF skeleton");
        goto cleanup;
    }

    flb_plg_info(ctx->ins, "Successfully eBPF shm started!");

    ctx->shm_skel = skel;

    /* Prepare CMetrics metric */
    ctx->shmget_total = cmt_counter_create(ctx->cmt, "ebpf", "shared_memory", "shmget_total",
                                           "The number of shmget called counts", 0, NULL);
    if (ctx->shmget_total == NULL) {
        return -1;
    }

    ctx->shmat_total = cmt_counter_create(ctx->cmt, "ebpf", "shared_memory", "shmat_total",
                                          "The number of shmat called counts", 0, NULL);
    if (ctx->shmat_total == NULL) {
        return -1;
    }

    ctx->shmdt_total = cmt_counter_create(ctx->cmt, "ebpf", "shared_memory", "shmdt_total",
                                          "The number of shmdt called counts", 0, NULL);
    if (ctx->shmat_total == NULL) {
        return -1;
    }

    ctx->shmctl_total = cmt_counter_create(ctx->cmt, "ebpf", "shared_memory", "shmctl_total",
                                          "The number of shmctl called counts", 0, NULL);
    if (ctx->shmat_total == NULL) {
        return -1;
    }

    ctx->shmget = cmt_gauge_create(ctx->cmt, "ebpf", "shared_memory", "shmget",
                                   "The current number of shmget called counts", 0, NULL);
    if (ctx->shmget == NULL) {
        return -1;
    }

    ctx->shmat = cmt_gauge_create(ctx->cmt, "ebpf", "shared_memory", "shmat",
                                   "The current number of shmat called counts", 0, NULL);
    if (ctx->shmat == NULL) {
        return -1;
    }

    ctx->shmdt = cmt_gauge_create(ctx->cmt, "ebpf", "shared_memory", "shmdt",
                                   "The current number of shmdt called counts", 0, NULL);
    if (ctx->shmdt == NULL) {
        return -1;
    }

    ctx->shmctl = cmt_gauge_create(ctx->cmt, "ebpf", "shared_memory", "shmctl",
                                   "The current number of shmctl called counts", 0, NULL);
    if (ctx->shmctl == NULL) {
        return -1;
    }

    return 0;

cleanup:
    shm_bpf__destroy(skel);
    ctx->shm_skel = NULL;

    return -1;
}

static void cb_ebpf_pause(void *data, struct flb_config *config)
{
    struct flb_in_ebpf *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void cb_ebpf_resume(void *data, struct flb_config *config)
{
    struct flb_in_ebpf *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int collect_oom_victim(struct flb_input_instance *ins,
                              struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf *ctx = in_context;
    struct bpf_map *map = ctx->oom_victim_skel->maps.oomkill;

    __u64 key = -1;
    __u64 next_key;
    __u64 remove_key;
    int err, fd = bpf_map__fd(map);
    __u8 value;
    __u32 count = 0;
    uint64_t ts = cmt_time_now();

    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        err = bpf_map_lookup_elem(fd, &next_key, &value);
        if (err < 0) {
            key = next_key;
            continue;
        }

        bpf_map_delete_elem(fd, &remove_key);

        count++;

        remove_key = key;

        key = next_key;
    }
    bpf_map_delete_elem(fd, &remove_key);

    cmt_counter_set(ctx->oom_victim, ts, (double)count, 0, NULL);

    return 0;
}

static int collect_vfsstat(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf *ctx = in_context;
    struct bpf_map *map = ctx->vfsstat_skel->maps.vfs_counts;
    int fd = bpf_map__fd(map);
    uint32_t kind = 0;
    uint64_t counts = 0;
    struct flb_vfsstat_t kind_stats = {};
    uint64_t ts = cmt_time_now();

    for (kind = 0; kind < __FLB_S_MAXSTAT; kind++) {
        counts = 0;
        if (!bpf_map_lookup_elem(fd, &kind, &counts));

        switch (kind) {
        case FLB_S_READ:
            kind_stats.read = counts;
            break;
        case FLB_S_WRITE:
            kind_stats.write = counts;
            break;
        case FLB_S_FSYNC:
            kind_stats.fsync = counts;
            break;
        case FLB_S_OPEN:
            kind_stats.open = counts;
            break;
        case FLB_S_CREATE:
            kind_stats.create = counts;
            break;
        case FLB_S_UNLINK:
            kind_stats.unlink = counts;
            break;
        case FLB_S_TRUNCATE:
            kind_stats.truncate = counts;
            break;
        case FLB_S_FALLOCATE:
            kind_stats.fallocate = counts;
            break;
        }
    }

    cmt_counter_set(ctx->vfs_read, ts, (double)kind_stats.read, 0, NULL);
    cmt_counter_set(ctx->vfs_write, ts, (double)kind_stats.write, 0, NULL);
    cmt_counter_set(ctx->vfs_fsync, ts, (double)kind_stats.fsync, 0, NULL);
    cmt_counter_set(ctx->vfs_open, ts, (double)kind_stats.open, 0, NULL);
    cmt_counter_set(ctx->vfs_create, ts, (double)kind_stats.create, 0, NULL);
    cmt_counter_set(ctx->vfs_unlink, ts, (double)kind_stats.unlink, 0, NULL);
    cmt_counter_set(ctx->vfs_truncate, ts, (double)kind_stats.truncate, 0, NULL);
    cmt_counter_set(ctx->vfs_fallocate, ts, (double)kind_stats.fallocate, 0, NULL);

    return 0;
}

static int collect_ipv4_tcpconnect(struct flb_input_instance *ins,
                                   struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf *ctx = in_context;
    struct ipv4_flow_key_t key = {};
    struct ipv4_flow_key_t next_key = {};
    struct ipv4_flow_key_t remove_key;
    struct bpf_map *map = ctx->tcpconnect_skel->maps.ipv4_counts;
    int err;
    int fd = bpf_map__fd(map);
    __u64 value;
    __u32 count = 0;
    uint64_t ts = cmt_time_now();

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        flb_plg_debug(ctx->ins, "ipv4_tcpconnect lookup err: %d", err);
        err = bpf_map_lookup_elem(fd, &next_key, &value);
        if (err < 0) {
            key = next_key;
            continue;
        }

        bpf_map_delete_elem(fd, &remove_key);

        count += value;
        flb_plg_debug(ctx->ins, "ipv4_tcpconnect count: %d", count);
        /* Reset value. */
        value = 0;

        remove_key = key;

        key = next_key;
    }

    bpf_map_delete_elem(fd, &remove_key);

    cmt_gauge_set(ctx->ipv4_tcpconnect, ts, (double)count, 0, NULL);

    return 0;
}

static int collect_ipv6_tcpconnect(struct flb_input_instance *ins,
                                   struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf *ctx = in_context;
    struct ipv6_flow_key_t key = {};
    struct ipv6_flow_key_t next_key = {};
    struct ipv6_flow_key_t remove_key;
    struct bpf_map *map = ctx->tcpconnect_skel->maps.ipv6_counts;
    int err;
    int fd = bpf_map__fd(map);
    __u64 value;
    __u32 count = 0;
    uint64_t ts = cmt_time_now();

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        err = bpf_map_lookup_elem(fd, &next_key, &value);
        flb_plg_debug(ctx->ins, "ipv6_tcpconnect lookup err: %d", err);
        if (err < 0) {
            key = next_key;
            continue;
        }

        bpf_map_delete_elem(fd, &remove_key);

        count += value;
        flb_plg_debug(ctx->ins, "ipv6_tcpconnect count: %d", count);
        /* Reset value. */
        value = 0;

        remove_key = key;

        key = next_key;
    }

    bpf_map_delete_elem(fd, &remove_key);

    cmt_gauge_set(ctx->ipv6_tcpconnect, ts, (double)count, 0, NULL);

    return 0;
}

static int collect_tcpconnect(struct flb_input_instance *ins,
                              struct flb_config *config, void *in_context)
{
    collect_ipv4_tcpconnect(ins, config, in_context);
    collect_ipv6_tcpconnect(ins, config, in_context);

    return 0;
}

static int collect_shm_current_values(struct flb_input_instance *ins,
                                      struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf *ctx = in_context;
    struct bpf_map *map = ctx->shm_skel->maps.pid_shms;
    __u32 key;
    __u32 next_key;
    __u32 remove_key;
    int err;
    int fd = bpf_map__fd(map);
    struct flb_shm_t shm = {};
    struct flb_shm_t total_shm = {};

    __u32 count = 0;
    uint64_t ts = cmt_time_now();

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        memset(&shm, 0, sizeof(struct flb_shm_t));
        err = bpf_map_lookup_elem(fd, &next_key, &shm);
        flb_plg_debug(ctx->ins, "pid_shms lookup err: %d", err);
        if (err < 0) {
            key = next_key;
            continue;
        }

        total_shm.get += shm.get;
        total_shm.at  += shm.at;
        total_shm.dt  += shm.dt;
        total_shm.ctl += shm.ctl;

        /* Reset values*/
        shm.get = 0;
        shm.at  = 0;
        shm.dt  = 0;
        shm.ctl = 0;

        bpf_map_delete_elem(fd, &remove_key);

        count++;
        flb_plg_debug(ctx->ins, "pid_shms count: %d", count);

        remove_key = key;

        key = next_key;
    }

    bpf_map_delete_elem(fd, &remove_key);

    cmt_gauge_set(ctx->shmget, ts, (double)total_shm.get, 0, NULL);
    cmt_gauge_set(ctx->shmat, ts, (double)total_shm.at, 0, NULL);
    cmt_gauge_set(ctx->shmdt, ts, (double)total_shm.dt, 0, NULL);
    cmt_gauge_set(ctx->shmctl, ts, (double)total_shm.ctl, 0, NULL);

    return 0;
}

static int collect_shm_cumulative_values(struct flb_input_instance *ins,
                                         struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf *ctx = in_context;
    struct bpf_map *map = ctx->shm_skel->maps.shm_counts;
    int fd = bpf_map__fd(map);
    uint32_t kind = 0;
    uint64_t counts = 0;
    struct flb_shm_t kind_stats = {};
    uint64_t ts = cmt_time_now();

    for (kind = 0; kind < __FLB_SHM_SYSCALL_END; kind++) {
        counts = 0;
        if (!bpf_map_lookup_elem(fd, &kind, &counts));

        switch (kind) {
        case FLB_SHM_GET_SYSCALL:
            kind_stats.get = counts;
            break;
        case FLB_SHM_AT_SYSCALL:
            kind_stats.at = counts;
            break;
        case FLB_SHM_DT_SYSCALL:
            kind_stats.dt = counts;
            break;
        case FLB_SHM_CTL_SYSCALL:
            kind_stats.ctl = counts;
            break;
        }
    }

    cmt_counter_set(ctx->shmget_total, ts, (double)kind_stats.get, 0, NULL);
    cmt_counter_set(ctx->shmat_total, ts, (double)kind_stats.at, 0, NULL);
    cmt_counter_set(ctx->shmdt_total, ts, (double)kind_stats.dt, 0, NULL);
    cmt_counter_set(ctx->shmctl_total, ts, (double)kind_stats.ctl, 0, NULL);

    return 0;
}

static int collect_shm(struct flb_input_instance *ins,
                       struct flb_config *config, void *in_context)
{
    collect_shm_current_values(ins, config, in_context);
    collect_shm_cumulative_values(ins, config, in_context);

    return 0;
}

static int cb_ebpf_collect(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf *ctx = in_context;
    int ret = -1;

    collect_oom_victim(ins, config, in_context);
    collect_vfsstat(ins, config, in_context);
    collect_tcpconnect(ins, config, in_context);
    collect_shm(ins, config, in_context);

    ret = flb_input_metrics_append(ins, NULL, 0, ctx->cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }

    return 0;
}

static int cb_ebpf_init(struct flb_input_instance *in,
                        struct flb_config *config,
                        void *data)
{
    struct flb_in_ebpf *ctx;
    (void) config;
    (void) data;
    int ret;

    ctx = flb_calloc(1, sizeof(struct flb_in_ebpf));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Initialize CMetrics */
    ctx->cmt = cmt_create();
    if (!ctx->cmt) {
        flb_plg_error(in, "could not initialize CMetrics");
        flb_free(ctx);
        return -1;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal configuration should be override. */
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(print_libbpf_log);

    struct rlimit rlim = {
        .rlim_cur = 512UL << 20, /* 512 MBs */
        .rlim_max = 512UL << 20, /* 512 MBs */
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        flb_plg_error(ctx->ins, "Failed to increase RLIMIT_MEMLOCK limit!");
        return -1;
    }

    ret = prepare_vsstat_ebpf(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not load eBPF vfsstat program");
        return -1;
    }

    ret = prepare_oom_victim_ebpf(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not load eBPF oom_victim program");
        return -1;
    }

    ret = prepare_tcpconnect_ebpf(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not load eBPF tcpconnect program");
        return -1;
    }

    ret = prepare_shm_ebpf(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not load eBPF tcpconnect program");
        return -1;
    }

    flb_input_set_context(in, ctx);

    ret = flb_input_set_collector_time(in,
                                       cb_ebpf_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set collector for eBPF input plugin");
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

static int cb_ebpf_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_ebpf *ctx = data;

    if (ctx->vfsstat_skel) {
        vfsstat_bpf__destroy(ctx->vfsstat_skel);
    }

    if (ctx->oom_victim_skel) {
        oom_victim_bpf__destroy(ctx->oom_victim_skel);
    }

    if (ctx->tcpconnect_skel) {
        tcpconnect_bpf__destroy(ctx->tcpconnect_skel);
    }

    if (ctx->shm_skel) {
        shm_bpf__destroy(ctx->shm_skel);
    }

    if (ctx->cmt) {
        cmt_destroy(ctx->cmt);
    }

    /* done */
    flb_free(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_INT, "interval_sec", "5",
        0, FLB_TRUE, offsetof(struct flb_in_ebpf, interval_sec),
        "Interval for polling eBPF information"
    },
    {
        FLB_CONFIG_MAP_INT, "interval_nsec", "0",
        0, FLB_TRUE, offsetof(struct flb_in_ebpf, interval_nsec),
        "Interval for polling eBPF information (nanosecond part)"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_ebpf_plugin = {
    .name         = "ebpf",
    .description  = "Handle eBPF programs to monitoring Linux Kernel events",
    .cb_init      = cb_ebpf_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_ebpf_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_ebpf_pause,
    .cb_resume    = cb_ebpf_resume,
    .cb_exit      = cb_ebpf_exit,
    .config_map   = config_map,
    .flags        = 0,
    .event_type   = FLB_INPUT_METRICS
};
