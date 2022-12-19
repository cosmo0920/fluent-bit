/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_pdh.h"
#include "we_pdh_system.h"
#include "we_util.h"
#include "we_metric.h"

int we_pdh_system_init(struct flb_we *ctx)
{
    ctx->system.operational = FLB_FALSE;

    struct cmt_gauge *g;
    struct cmt_counter *c;

    c = cmt_counter_create(ctx->cmt, "windows", "system", "context_switches_total",
                           "Total number of context switches",
                           0, NULL);

    if (!c) {
        return -1;
    }
    ctx->system.context_switches = c;

    c = cmt_counter_create(ctx->cmt, "windows", "system", "exception_dispatches_total",
                           "Total number of exception_dispatches",
                           0, NULL);

    if (!c) {
        return -1;
    }
    ctx->system.exception_dispatches = c;

    g = cmt_gauge_create(ctx->cmt, "windows", "system", "processor_queue",
                           "Length of processor queues",
                           0, NULL);

    if (!g) {
        return -1;
    }
    ctx->system.processor_queue = g;

    c = cmt_counter_create(ctx->cmt, "windows", "system", "system_calls_total",
                           "Total number of system calls",
                           0, NULL);

    if (!c) {
        return -1;
    }
    ctx->system.system_calls = c;

    g = cmt_gauge_create(ctx->cmt, "windows", "system", "system_up_time",
                           "System boot time",
                           0, NULL);

    if (!g) {
        return -1;
    }
    ctx->system.system_up_time = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "system", "threads",
                           "Current number of threads",
                           0, NULL);

    if (!g) {
        return -1;
    }
    ctx->system.threads = g;

    ctx->system.operational = FLB_TRUE;

    return 0;
}

int we_pdh_system_exit(struct flb_we *ctx)
{
    ctx->system.operational = FLB_FALSE;

    return 0;
}

int we_pdh_system_update(struct flb_we *ctx)
{
    uint64_t timestamp = 0;

    if (!ctx->system.operational) {
        flb_plg_error(ctx->ins, "cpu collector not yet in operational state");

        return -1;
    }

    timestamp = cfl_time_now();

    cmt_counter_set(ctx->system.context_switches, timestamp, we_pdh_single_val("\\System\\Context Switches/sec"), 0, NULL);
    cmt_counter_set(ctx->system.exception_dispatches, timestamp, we_pdh_single_val("\\System\\Exception Dispatches/sec"), 0, NULL);
    cmt_gauge_set(ctx->system.processor_queue, timestamp, we_pdh_single_val("\\System\\Processor Queue Length"), 0, NULL);
    cmt_counter_set(ctx->system.system_calls, timestamp, we_pdh_single_val("\\System\\System Calls/sec"), 0, NULL);
    cmt_gauge_set(ctx->system.system_up_time, timestamp, we_pdh_single_val("\\System\\System Up Time"), 0, NULL);
    cmt_gauge_set(ctx->system.threads, timestamp, we_pdh_single_val("\\System\\Threads"), 0, NULL);

    return 0;
}
