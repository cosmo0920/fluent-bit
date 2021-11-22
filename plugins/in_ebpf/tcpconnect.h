/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef TCPCONNECT_H
#define TCPCONNECT_H

#ifndef AF_INET
# define AF_INET  2
#endif
#ifndef AF_INET6
# define AF_INET6 10
#endif
#define MAX_ENTRIES 8192

// separate flow keys per address family
struct ipv4_flow_key_t {
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
};

struct ipv6_flow_key_t {
    __u8 saddr[16];
    __u8 daddr[16];
    __u16 dport;
};

#endif
