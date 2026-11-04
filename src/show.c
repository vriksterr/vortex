#include "common.h"
#include "ctl.h"
#include "argz.h"

static void
vx_show_error(const char *name, struct vmux_error *err)
{
    if (!err->count)
        return;

    char addr[INET6_ADDRSTRLEN];
    vx_toaddr(addr, sizeof(addr), &err->addr);

    if (err->addr.sa.sa_family == AF_INET6)
        printf("error %s count %"PRIu64" from [%s]:%"PRIu16"\n",
                name, err->count, addr, vx_get_port(&err->addr));
    else
        printf("error %s count %"PRIu64" from %s:%"PRIu16"\n",
                name, err->count, addr, vx_get_port(&err->addr));
}

static int
vx_show_errors(int fd, const char *peer)
{
    struct ctl_msg req = {
        .type = CTL_ERRORS,
    }, res = {0};

    if (peer && strlen(peer) < sizeof(req.peer))
        memcpy(req.peer, peer, strlen(peer) + 1);

    if (ctl_reply(fd, &res, &req))
        return -1;

    vx_show_error("decrypt",   &res.errors.decrypt);
    vx_show_error("clocksync", &res.errors.clocksync);
    vx_show_error("keyx",      &res.errors.keyx);

    return 0;
}

static int
vx_show_status(int fd)
{
    struct ctl_msg req = {
        .type = CTL_STATUS,
    }, res = {0};

    if (ctl_reply(fd, &res, &req))
        return -1;

    char local[INET6_ADDRSTRLEN];
    char remote[INET6_ADDRSTRLEN];

    vx_toaddr(local, sizeof(local), &res.status.local);
    vx_toaddr(remote, sizeof(remote), &res.status.remote);

    /* local/remote always share one address family -- they're the two
     * ends of a single UDP socket -- so one check covers both. */
    const char *fmt = (res.status.local.sa.sa_family == AF_INET6)
                     ? "tunnel %s\n"
                       "local  [%s]:%"PRIu16"\n"
                       "remote [%s]:%"PRIu16"\n"
                       "pid    %li\n"
                       "mtu    %zu\n"
                       "cipher %s\n"
                     : "tunnel %s\n"
                       "local  %s:%"PRIu16"\n"
                       "remote %s:%"PRIu16"\n"
                       "pid    %li\n"
                       "mtu    %zu\n"
                       "cipher %s\n";

    if (res.status.hub) {
        /* a multi-client tunnel has no single remote: its clients are listed
         * by `peer list` */
        const int v6 = res.status.local.sa.sa_family == AF_INET6;

        printf("tunnel %s\n", res.tun_name);
        printf(v6 ? "local  [%s]:%"PRIu16"\n" : "local  %s:%"PRIu16"\n",
               local, vx_get_port(&res.status.local));
        printf("mode   multi-client (%u client%s)\n", res.status.peers,
               res.status.peers == 1 ? "" : "s");
        printf("pid    %li\n", res.status.pid);
        printf("mtu    %zu\n", res.status.mtu);
        printf("cipher %s\n", VX_CIPHER(res.status.cipher));
        printf("dropped  no-route %"PRIu64"  unknown-source %"PRIu64
               "  rate-limited-lookups %"PRIu64"\n",
               res.status.hubstats.tx_drop_noroute,
               res.status.hubstats.rx_drop_unknown,
               res.status.hubstats.rx_drop_limited);
        return 0;
    }
    printf(fmt,
            res.tun_name,
            local, vx_get_port(&res.status.local),
            remote, vx_get_port(&res.status.remote),
            res.status.pid,
            res.status.mtu,
            VX_CIPHER(res.status.cipher));

    return 0;
}

int
vx_show(int argc, char **argv, void *data)
{
    const char *dev = NULL;
    const char *peer = NULL;

    struct argz z[] = {
        {"dev",    "Tunnel device", vx_argz_dev, &dev},
        {"errors", "Show tunnel errors"              },
        {"peer",   "Only this client of a multi-client tunnel", argz_str, &peer},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return -1;
    }
    int ret = argz_is_set(z, "errors") ? vx_show_errors(fd, peer)
                                       : vx_show_status(fd);
    if (ret == -1 && errno)
        perror("show");

    ctl_delete(fd);

    return ret;
}
