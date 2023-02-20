/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#ifdef FLB_SYSTEM_WINDOWS

#include "win32_tls.h"

int win32_tls_create(DWORD *key)
{
    DWORD dkey = TlsAlloc();
    if(dkey != 0xFFFFFFFF){
        *key = dkey;
        return 0;
    }
    else {
        return EAGAIN;
    }
}

void *win32_tls_get(DWORD key)
{
    return TlsGetValue(key);
}

void win32_tls_set(DWORD key, void *ptr)
{
    if (FAILED(TlsSetValue(key, ptr))) {
        flb_error("TlsSetValue() error");
    }
}


int win32_tls_delete(DWORD key)
{
    if(TlsFree(key)){
        return 0;
    }
    else{
        return EINVAL;
    }
}

#endif
