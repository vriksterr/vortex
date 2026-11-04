#pragma once

#include "common.h"
#include "ctl.h"
#include "argz.h"

/* Everything vx_bind() parsed that the multi-client mode needs. */
struct vx_hub_args {
    const char *dev;
    struct vx_argz_addr local;
    int chacha;
    int persist;
    int qlen_set;
    unsigned long long qlen;
    unsigned long long mtu;       /* 0 = follow the largest client */
    const char *peers_file;
};

int vx_hub_run (const struct vx_hub_args *);

/* Shared with bind.c */
int vx_read_keyfile (unsigned char *key, const char *keyfile);
int vx_tun_write_validated (int fd, const void *buf, size_t size);

/* peer.c: parsing of "NAME key FILE allowed CIDR ..." words, shared by the
 * `peer` command and the peers file. `set` = modify rather than create. */
int  vx_peer_parse (int argc, char **argv, int set, struct ctl_peer *out,
                    const char **dev);
void vx_peer_format_prefix (char *dst, size_t size, const struct vmux_prefix *);
int  vx_peers_load (struct vmux_hub *, const char *file);
int  vx_hub_peer_apply (struct vmux_hub *, int type, struct ctl_peer *);
