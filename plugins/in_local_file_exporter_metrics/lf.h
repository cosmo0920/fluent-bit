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

#ifndef FLB_LOCAL_FILE_EXPORTER_H
#define FLB_LOCAL_FILE_EXPORTER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_metrics.h>

/* utils: scan content type expected */
#define LF_SCAN_FILE      1
#define LF_SCAN_DIR       2

struct flb_lf {
    /* configuration */
    flb_sds_t path_textfile;
    int scrape_interval;

    int coll_fd;                                      /* collector fd     */
    struct cmt *cmt;                                  /* cmetrics context */
    struct flb_input_instance *ins;                   /* input instance   */
    struct flb_callback *callback;                    /* metric callback */
    struct mk_list *metrics;                          /* enabled metrics */

    /* Individual intervals for metrics */
    int textfile_scrape_interval;

    int coll_textfile_fd;                               /* collector fd (textfile)  */

    /* testfile */
    struct cmt_counter *load_errors;
};

#endif
