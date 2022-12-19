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

#include <fluent-bit/flb_log.h>

#include <winperf.h>
#include <pdh.h>

double we_pdh_single_val(char* path)
{
    PDH_STATUS status = ERROR_SUCCESS;
    HQUERY query = NULL;
    HCOUNTER counter;
    DWORD type;
    PDH_RAW_COUNTER value;
    double val = 0;

    if ((status = PdhValidatePathA(path)) != ERROR_SUCCESS) {
        flb_error("query path %s does not exist");
        goto nonexistent;
    }

    if ((status = PdhOpenQuery(NULL, 0, &query)) != ERROR_SUCCESS) {
        goto clean;
    }

    if ((status = PdhAddCounter(query, path, 0, &counter)) != ERROR_SUCCESS) {
        goto clean;
    }

    if ((status = PdhCollectQueryData(query)) != ERROR_SUCCESS) {
        goto clean;
    }

    if ((status = PdhGetRawCounterValue(counter, &type, &value)) != ERROR_SUCCESS) {
        goto clean;
    }
    val = value.FirstValue;

clean:

    if (status != ERROR_SUCCESS) {
        flb_warn("query is failed with status %d", status);
    }

    if (query != NULL) {
        PdhCloseQuery(query);
    }

nonexistent:

    return val;
}
