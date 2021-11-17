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

#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>

#include <bpf/libbpf.h>
#include <msgpack.h>
#include <sys/resource.h>
#include "minimal.skel.h"
#include "ebpf.h"

static int print_libbpf_log(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) {
        return 0;
    }
    return vfprintf(stderr, fmt, args);
}

static int prepare_ebpf(struct flb_filter_ebpf *ctx)
{
    struct minimal_bpf *skel;
    int err;

    /* Open BPF application */
    skel = minimal_bpf__open();
    if (!skel) {
        flb_plg_error(ctx->f_ins, "Failed to open BPF skeleton");
        return 1;
    }

        /* ensure BPF program only handles write() syscalls from our process */
    skel->bss->my_pid = getpid();

    /* Load & verify BPF programs */
    err = minimal_bpf__load(skel);
    if (err) {
        flb_plg_error(ctx->f_ins, "Failed to load and verify BPF skeleton");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = minimal_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    flb_plg_info(ctx->f_ins,
                 "Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
                 "to see output of the BPF programs.");

    ctx->skel = skel;

    return 0;

cleanup:
    minimal_bpf__destroy(skel);

    ctx->skel = NULL;

    return -1;
}

static int cb_ebpf_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    struct flb_filter_ebpf *ctx;
    (void) f_ins;
    (void) config;
    (void) data;
    int ret;

    ctx = flb_calloc(1, sizeof(struct flb_filter_ebpf));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->f_ins = f_ins;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(print_libbpf_log);

    struct rlimit rlim = {
        .rlim_cur = 512UL << 20, /* 512 MBs */
        .rlim_max = 512UL << 20, /* 512 MBs */
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        flb_plg_error(ctx->f_ins, "Failed to increase RLIMIT_MEMLOCK limit!");
        return -1;
    }

    ret = prepare_ebpf(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->f_ins, "could not load eBPF program");
        return -1;
    }


    return 0;
}

static int cb_ebpf_filter(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          void **out_buf, size_t *out_bytes,
                          struct flb_filter_instance *f_ins,
                          void *filter_context,
                          struct flb_config *config)
{
    size_t off = 0, cnt = 0;
    (void) out_buf;
    (void) out_bytes;
    (void) f_ins;
    (void) filter_context;
    (void) config;

    /* trigger our BPF program */
    fprintf(stderr, ".");

    return FLB_FILTER_NOTOUCH;
}

static int cb_ebpf_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_filter_ebpf *ctx = data;

    if (ctx->skel) {
        minimal_bpf__destroy(ctx->skel);
    }

    /* done */
    flb_free(ctx);

    return 0;
}

struct flb_filter_plugin filter_ebpf_plugin = {
    .name         = "ebpf",
    .description  = "Filter to handle eBPF",
    .cb_init      = cb_ebpf_init,
    .cb_filter    = cb_ebpf_filter,
    .cb_exit      = cb_ebpf_exit,
    .flags        = 0
};
