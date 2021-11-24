/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef SHM_H
#define SHM_H

struct flb_shm_t {
    __u64 get;
    __u64 at;
    __u64 dt;
    __u64 ctl;
};

enum flb_shm_counters {
    FLB_SHM_GET_SYSCALL,
    FLB_SHM_AT_SYSCALL,
    FLB_SHM_DT_SYSCALL,
    FLB_SHM_CTL_SYSCALL,

    __FLB_SHM_SYSCALL_END
};

#endif
