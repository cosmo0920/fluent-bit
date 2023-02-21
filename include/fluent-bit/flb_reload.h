/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifndef FLB_RELOAD_H
#define FLB_RELOAD_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_format.h>

struct flb_reload_ctx {
    struct mk_event event;
    flb_pipefd_t signal_channels[2];
    struct flb_config *config;
    void *event_loop;
};

int flb_reload_property_check_all(struct flb_config *config);
int flb_reload_reconstruct_cf(struct flb_cf *src_cf, struct flb_cf *dest_cf);
int flb_reload(flb_ctx_t *ctx, struct flb_cf *cf_opts);
struct flb_reload_ctx *flb_reload_context_create(struct flb_config *ctx);
int flb_reload_context_call(struct flb_reload_ctx *reload);
int flb_reload_context_destroy(struct flb_reload_ctx *reload);

#endif
