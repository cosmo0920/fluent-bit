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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "lf.h"
#include "lf_config.h"

/* collectors */
#include "lf_textfile.h"

static int lf_timer_textfile_metrics_cb(struct flb_input_instance *ins,
                                        struct flb_config *config, void *in_context)
{
    struct flb_le *ctx = in_context;

    lf_textfile_update(ctx);

    return 0;
}

struct flb_lf_callback {
    char *name;
    void (*func)(char *, void *, void *);
};

static int lf_update_cb(struct flb_lf *ctx, char *name);

static void update_metrics(struct flb_input_instance *ins, struct flb_lf *ctx)
{
    int ret;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    /* Update our metrics */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            ret = flb_callback_exists(ctx->callback, entry->str);
            if (ret == FLB_TRUE) {
                lf_update_cb(ctx, entry->str);
            }
            else {
                flb_plg_debug(ctx->ins, "Callback for metrics '%s' is not registered", entry->str);
            }
        }
    }
}

/*
 * Update the metrics, this function is invoked every time 'scrape_interval'
 * expires.
 */
static int cb_lf_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int ret;
    struct flb_lf *ctx = in_context;

    update_metrics(ins, ctx);

    /* Append the updated metrics */
    ret = flb_input_metrics_append(ins, NULL, 0, ctx->cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }

    return 0;
}

static void lf_textfile_update_cb(char *name, void *p1, void *p2)
{
    struct flb_lf *ctx = p1;

    lf_textfile_update(ctx);
}

static int lf_update_cb(struct flb_lf *ctx, char *name)
{
    int ret;

    ret = flb_callback_do(ctx->callback, name, ctx, NULL);
    return ret;
}

/*
 * Callbacks Table
 */
struct flb_lf_callback lf_callbacks[] = {
    /* metrics */
    { "textfile", lf_textfile_update_cb },
    { 0 }
};

static int in_lf_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    int metric_idx = -1;
    struct flb_lf *ctx;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct flb_lf_callback *cb;

    /* Create plugin context */
    ctx = flb_lf_config_create(in, config);
    if (!ctx) {
        flb_errno();
        return -1;
    }

    /* Initialize fds */
    ctx->coll_textfile_fd = -1;

    ctx->callback = flb_callback_create(in->name);
    if (!ctx->callback) {
        flb_plg_error(ctx->ins, "Create callback failed");
        return -1;
    }

    /* Associate context with the instance */
    flb_input_set_context(in, ctx);

    /* Create the collector */
    ret = flb_input_set_collector_time(in,
                                       cb_lf_collect,
                                       ctx->scrape_interval, 0,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not set collector for Node Exporter Metrics plugin");
        return -1;
    }
    ctx->coll_fd = ret;

    /* Check and initialize enabled metrics */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            ret = flb_callback_exists(ctx->callback, entry->str);

            if (ret == FLB_FALSE) {
                if (strncmp(entry->str, "textfile", 8) == 0) {
                    if (ctx->textfile_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 0;
                    }
                    else if (ctx->textfile_scrape_interval > 0) {
                        /* Create the filefd collector */
                        ret = flb_input_set_collector_time(in,
                                                           lf_timer_textfile_metrics_cb,
                                                           ctx->textfile_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set textfile collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_textfile_fd = ret;
                    }
                    lf_textfile_init(ctx);
                }
                else {
                    flb_plg_warn(ctx->ins, "Unknown metrics: %s", entry->str);
                    metric_idx = -1;
                }

                if (metric_idx >= 0) {
                    cb = &lf_callbacks[metric_idx];
                    ret = flb_callback_set(ctx->callback, cb->name, cb->func);
                    if (ret == -1) {
                        flb_plg_error(ctx->ins, "error setting up default "
                                      "callback '%s'", cb->name);
                    }
                }
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "No metrics is specified");

        return -1;
    }

    return 0;
}


static int in_lf_exit(void *data, struct flb_config *config)
{
    int ret;
    struct flb_lf *ctx = data;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    if (!ctx) {
        return 0;
    }

    /* Teardown for callback tied up resources */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            ret = flb_callback_exists(ctx->callback, entry->str);

            if (ret == FLB_TRUE) {
                if (strncmp(entry->str, "textfile", 8) == 0) {
                    /* nop */
                }
                else {
                    flb_plg_warn(ctx->ins, "Unknown metrics: %s", entry->str);
                }
            }
        }
    }

    /* destroy callback context */
    if (ctx->callback) {
        flb_callback_destroy(ctx->callback);
    }

    flb_lf_config_destroy(ctx);

    return 0;
}

static void in_lf_pause(void *data, struct flb_config *config)
{
    struct flb_lf *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
    if (ctx->coll_textfile_fd != -1) {
        flb_input_collector_pause(ctx->coll_textfile_fd, ctx->ins);
    }
}

static void in_lf_resume(void *data, struct flb_config *config)
{
    struct flb_lf *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
    if (ctx->coll_textfile_fd != -1) {
        flb_input_collector_resume(ctx->coll_textfile_fd, ctx->ins);
    }
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "5",
     0, FLB_TRUE, offsetof(struct flb_lf, scrape_interval),
     "scrape interval to collect metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.textfile.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_lf, textfile_scrape_interval),
     "scrape interval to collect textfile metrics from the node."
    },

    {
     FLB_CONFIG_MAP_CLIST, "metrics",
     "textfile",
     0, FLB_TRUE, offsetof(struct flb_lf, metrics),
     "Comma separated list of keys to enable metrics."
    },

    {
     FLB_CONFIG_MAP_STR, "collector.textfile.path", NULL,
     0, FLB_TRUE, offsetof(struct flb_lf, path_textfile),
     "Specify path to collect textfile metrics from the node."
    },

    /* EOF */
    {0}
};

struct flb_input_plugin in_local_file_exporter_metrics_plugin = {
    .name         = "local_file_exporter_metrics",
    .description  = "Local File Exporter Metrics (Prometheus Compatible)",
    .cb_init      = in_lf_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_lf_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_lf_pause,
    .cb_resume    = in_lf_resume,
    .cb_exit      = in_lf_exit,
    .flags        = FLB_INPUT_THREADED
};
