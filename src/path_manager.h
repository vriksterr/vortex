#pragma once

#include "../vmux/vmux.h"

#include <net/if.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

enum vx_path_availability {
    VX_PATH_AVAILABLE = 0,
    VX_PATH_INTERFACE_DOWN,
    VX_PATH_WAITING_ADDRESS,
    VX_PATH_ADMIN_DOWN,
};

struct vx_managed_path {
    char ifname[IFNAMSIZ];
    unsigned int ifindex;
    unsigned int bound_ifindex;
    union vmux_sockaddr current_local;
    union vmux_sockaddr bound_local;
    union vmux_sockaddr remote;
    uint16_t sock; /* vmux socket-pool index this sub-flow uses; a
                     * logical path with N sub-flows occupies N
                     * vx_managed_path entries, one per sock 0..N-1 */
    struct vmux_path_conf desired_conf;
    int desired_up;
    int link_up;
    int address_ready;
    int runtime_bound;
    int runtime_active;
    int config_dirty;
    int bind_dev;            /* 0 = off, 1 = on (default): the sub-flow's socket
                              * is bound to the interface (SO_BINDTODEVICE), so
                              * no route, rule or firewall mark can send its
                              * packets out another one */
    unsigned int so_ifindex; /* ifindex the socket is currently bound to (0 =
                              * not bound) */
    int bind_warned;
};

struct vx_path_manager {
    struct vx_managed_path *path; /* grows as sub-flows are added: no fixed limit */
    unsigned int count, cap;
    int req_bind;                 /* what the request being handled asked for:
                                   * 0 = unchanged, 1 = off, 2 = on */
};

struct vx_managed_status {
    char ifname[IFNAMSIZ];
    unsigned int ifindex;
    enum vx_path_availability availability;
    struct vmux_path path;
};

void vx_path_manager_init(struct vx_path_manager *);
int vx_path_manager_set(struct vx_path_manager *, struct vmux *, const char *,
                        unsigned int sock, struct vmux_path_conf *);
int vx_path_manager_reconcile(struct vx_path_manager *, struct vmux *);
unsigned int vx_path_manager_status(struct vx_path_manager *, struct vmux *,
                                    const char *, union vmux_sockaddr *,
                                    struct vx_managed_status *, unsigned int);
