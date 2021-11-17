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

#include <bpf/libbpf.h>
#include <msgpack.h>
#include <sys/resource.h>
#include "ebpf.h"
#include "vfsstat.skel.h"
#include "vfsstat.h"

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

    flb_plg_info(ctx->ins,
                 "Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
                 "to see output of the BPF programs.");

    ctx->vfsstat_skel = skel;

    return 0;

cleanup:
    vfsstat_bpf__destroy(skel);
    ctx->vfsstat_skel = NULL;

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

static int cb_ebpf_collect(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf *ctx = in_context;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    int count = 8;

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);

    msgpack_pack_map(&mp_pck, count);

    /* vfs_read */
    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "vfs_read", 8);
    msgpack_pack_uint64(&mp_pck, ctx->vfsstat_skel->bss->stats[FLB_S_READ]);

    /* vfs_write */
    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "vfs_write", 9);
    msgpack_pack_uint64(&mp_pck, ctx->vfsstat_skel->bss->stats[FLB_S_WRITE]);

    /* vfs_fsync */
    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "vfs_fsync", 9);
    msgpack_pack_uint64(&mp_pck, ctx->vfsstat_skel->bss->stats[FLB_S_FSYNC]);

    /* vfs_open */
    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "vfs_open", 8);
    msgpack_pack_uint64(&mp_pck, ctx->vfsstat_skel->bss->stats[FLB_S_OPEN]);

    /* vfs_create */
    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "vfs_create", 10);
    msgpack_pack_uint64(&mp_pck, ctx->vfsstat_skel->bss->stats[FLB_S_CREATE]);

    /* vfs_unlink */
    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "vfs_unlink", 10);
    msgpack_pack_uint64(&mp_pck, ctx->vfsstat_skel->bss->stats[FLB_S_UNLINK]);

    /* vfs_truncate */
    msgpack_pack_str(&mp_pck, 12);
    msgpack_pack_str_body(&mp_pck, "vfs_truncate", 12);
    msgpack_pack_uint64(&mp_pck, ctx->vfsstat_skel->bss->stats[FLB_S_TRUNCATE]);

    /* vfs_fallocate */
    msgpack_pack_str(&mp_pck, 13);
    msgpack_pack_str_body(&mp_pck, "vfs_fallocate", 13);
    msgpack_pack_uint64(&mp_pck, ctx->vfsstat_skel->bss->stats[FLB_S_FALLOCATE]);

    flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

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
    const char *pval = NULL;

    ctx = flb_calloc(1, sizeof(struct flb_in_ebpf));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;
    /* Collection time setting */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) > 0) {
        ctx->interval_sec = atoi(pval);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }
    ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;

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
        flb_plg_error(ctx->ins, "could not load eBPF program");
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

    /* done */
    flb_free(ctx);

    return 0;
}

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
    .flags        = 0
};
