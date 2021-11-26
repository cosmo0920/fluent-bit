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

#ifndef FLB_FILTER_EBPF_H
#define FLB_FILTER_EBPF_H

/* Default collection time: every 1 second (0 nanoseconds) */
#define DEFAULT_INTERVAL_SEC    1
#define DEFAULT_INTERVAL_NSEC   0

struct flb_in_ebpf {
    int coll_fd;       /* collector id/fd            */
    int interval_sec;  /* interval collection time (Second) */
    int interval_nsec; /* interval collection time (Nanosecond) */
    struct cmt *cmt;
    /* OOM Victim */
    struct cmt_counter *oom_victim;

    /* VFS stats */
    struct cmt_counter *vfs_read;
    struct cmt_counter *vfs_write;
    struct cmt_counter *vfs_fsync;
    struct cmt_counter *vfs_open;
    struct cmt_counter *vfs_create;
    struct cmt_counter *vfs_unlink;
    struct cmt_counter *vfs_truncate;
    struct cmt_counter *vfs_fallocate;

    /* TCP connect */
    struct cmt_gauge *ipv4_tcpconnect;
    struct cmt_gauge *ipv6_tcpconnect;

    /* Shared memory (SHM) */
    struct cmt_counter *shmget_total;
    struct cmt_counter *shmat_total;
    struct cmt_counter *shmdt_total;
    struct cmt_counter *shmctl_total;
    struct cmt_gauge *shmget;
    struct cmt_gauge *shmat;
    struct cmt_gauge *shmdt;
    struct cmt_gauge *shmctl;

    struct vfsstat_bpf *vfsstat_skel;
    struct oom_victim_bpf *oom_victim_skel;
    struct tcpconnect_bpf *tcpconnect_skel;
    struct shm_bpf *shm_skel;
    struct flb_input_instance *ins;
};

#endif
