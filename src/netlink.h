#pragma once

#include "../vmux/vmux.h"

#include <net/if.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

struct vx_link_info {
    unsigned int ifindex;
    int link_up;
    int address_ready;
    union vmux_sockaddr local;
};

int vx_netlink_open(void);
int vx_netlink_drain(int);
int vx_netlink_resolve(const char *, int, const union vmux_sockaddr *,
                       struct vx_link_info *);
