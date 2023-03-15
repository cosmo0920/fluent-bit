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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_sds.h>
#include "lf.h"

/* required by stat(2), open(2) */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <glob.h>

int lf_utils_path_scan(struct flb_lf *ctx, const char *mount, const char *path,
                       int expected, struct mk_list *list)
{
    int i;
    int ret;
    glob_t globbuf;
    struct stat st;
    char real_path[2048];

    if (!path) {
        return -1;
    }

    /* Safe reset for globfree() */
    globbuf.gl_pathv = NULL;

    /* Scan the real path */
    snprintf(real_path, sizeof(real_path) - 1, "%s%s", mount, path);
    ret = glob(real_path, GLOB_TILDE | GLOB_ERR, NULL, &globbuf);
    if (ret != 0) {
        switch (ret) {
        case GLOB_NOSPACE:
            flb_plg_error(ctx->ins, "no memory space available");
            return -1;
        case GLOB_ABORTED:
            flb_plg_error(ctx->ins, "read error, check permissions: %s", path);
            return -1;;
        case GLOB_NOMATCH:
            ret = stat(path, &st);
            if (ret == -1) {
                flb_plg_debug(ctx->ins, "cannot read info from: %s", path);
            }
            else {
                ret = access(path, R_OK);
                if (ret == -1 && errno == EACCES) {
                    flb_plg_error(ctx->ins, "NO read access for path: %s", path);
                }
                else {
                    flb_plg_debug(ctx->ins, "NO matches for path: %s", path);
                }
            }
            return -1;
        }
    }

    if (globbuf.gl_pathc <= 0) {
        globfree(&globbuf);
        return -1;
    }

    /* Initialize list */
    flb_slist_create(list);

    /* For every entry found, generate an output list */
    for (i = 0; i < globbuf.gl_pathc; i++) {
        ret = stat(globbuf.gl_pathv[i], &st);
        if (ret != 0) {
            continue;
        }

        if ((expected == LF_SCAN_FILE && S_ISREG(st.st_mode)) ||
            (expected == LF_SCAN_DIR && S_ISDIR(st.st_mode))) {

            /* Compose the path */
            ret = flb_slist_add(list, globbuf.gl_pathv[i]);
            if (ret != 0) {
                globfree(&globbuf);
                flb_slist_destroy(list);
                return -1;
            }
        }
    }

    globfree(&globbuf);
    return 0;
}
