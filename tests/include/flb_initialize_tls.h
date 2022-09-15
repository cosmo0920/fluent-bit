/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef FLB_INITALIZE_TLS_H
#define FLB_INITALIZE_TLS_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_mem.h>

struct flb_config *test_env_config;

static void flb_test_logger_env_create()
{
    test_env_config = flb_calloc(1, sizeof(struct flb_config));
    if (!test_env_config) {
        flb_errno();
        return;
    }

    /* Initialize linked lists */
    mk_list_init(&test_env_config->workers);

    if (flb_log_create(test_env_config, FLB_LOG_STDERR, FLB_LOG_INFO, NULL) == NULL) {
        free(test_env_config);
        return;
    }

    return;
}

static void flb_test_logger_env_destroy()
{
    flb_log_destroy(test_env_config->log, test_env_config);
    flb_worker_exit(test_env_config);
    free(test_env_config);
}

#endif
