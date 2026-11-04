#pragma once

#include "../vmux/vmux.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

#define CTL_ERROR_NONE (-2)
#define CTL_ERROR_MANY (-3)

enum ctl_type {
    CTL_NONE = 0,
    CTL_STATUS,
    CTL_CONF,
    CTL_PATH_STATUS,
    CTL_PATH_CONF,
    CTL_ERRORS,
    CTL_PEER_ADD,
    CTL_PEER_SET,
    CTL_PEER_DEL,
    CTL_PEER_LIST,
};

/* A client of a multi-client (hub) tunnel. Used both as the request for
 * peer add/set (the fields to apply) and as the reply for peer list/show
 * (info). */
struct ctl_peer {
    char name[VMUX_HUB_NAME_MAX];
    char keyfile[256];            /* add only: absolute path to its key */
    int allowed_set;              /* replace the allowed list */
    unsigned int allowed_count;
    struct vmux_prefix allowed[VMUX_HUB_ALLOWED_MAX];
    struct vmux_policy policy;     /* fields to enforce (bits in policy.set) */
    unsigned int unset;           /* VMUX_POLICY_* bits to release */
    struct vmux_conf conf;         /* tunables; 0 = unchanged, as for CTL_CONF */
    struct vmux_hub_peer_info info; /* replies */
};

struct ctl_msg {
    enum ctl_type type;
    int reply, ret;
    char tun_name[64];
    char ifname[IFNAMSIZ];
    unsigned int ifindex;
    int path_availability;
    unsigned int connections; /* requested sub-flow count for CTL_PATH_CONF;
                                * 0 = unspecified/unchanged, 1 = default */
    char peer[VMUX_HUB_NAME_MAX]; /* selects one client of a hub tunnel for
                                   * path/show/set requests; empty = all */
    union {
        struct {
            long pid;
            size_t mtu;
            int cipher;
            union vmux_sockaddr local;
            union vmux_sockaddr remote;
            int hub;                  /* multi-client tunnel */
            unsigned int peers;       /* active clients */
            struct vmux_hub_stats hubstats;
        } status;
        struct vmux_conf conf;
        struct vmux_path path;
        struct vmux_errors errors;
        struct ctl_peer peer_spec;
    };
};

union ctl_sun {
    struct sockaddr sa;
    struct sockaddr_un sun;
};

char *ctl_rundir  (char *, size_t);
int   ctl_create  (const char *);
int   ctl_connect (const char *);
int   ctl_reply   (int, struct ctl_msg *, struct ctl_msg *);
void  ctl_delete  (int);
void  ctl_foreach (void (*cb) (const char *));

void ctl_explain_connect (int);
