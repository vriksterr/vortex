#include "common.h"
#include "netlink.h"
#include "path_manager.h"

static int
vx_sockaddr_addr_equal(const union vmux_sockaddr *a,
                       const union vmux_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 0;
    if (a->sa.sa_family == AF_INET)
        return !memcmp(&a->sin.sin_addr, &b->sin.sin_addr,
                       sizeof(a->sin.sin_addr));
    if (a->sa.sa_family == AF_INET6)
        return !memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr,
                       sizeof(a->sin6.sin6_addr));
    return 0;
}

static int
vx_sockaddr_port_equal(const union vmux_sockaddr *a,
                       const union vmux_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 0;
    if (a->sa.sa_family == AF_INET)
        return a->sin.sin_port == b->sin.sin_port;
    if (a->sa.sa_family == AF_INET6)
        return a->sin6.sin6_port == b->sin6.sin6_port;
    return 0;
}

static int
vx_remote_equal(const union vmux_sockaddr *a, const union vmux_sockaddr *b)
{
    return vx_sockaddr_addr_equal(a, b) && vx_sockaddr_port_equal(a, b);
}

static int
vx_remote_matches(const union vmux_sockaddr *filter,
                  const union vmux_sockaddr *remote)
{
    if (!filter || !filter->sa.sa_family)
        return 1;
    if (!vx_sockaddr_addr_equal(filter, remote))
        return 0;
    if (filter->sa.sa_family == AF_INET && !filter->sin.sin_port)
        return 1;
    if (filter->sa.sa_family == AF_INET6 && !filter->sin6.sin6_port)
        return 1;
    return vx_sockaddr_port_equal(filter, remote);
}

void
vx_path_manager_init(struct vx_path_manager *manager)
{
    memset(manager, 0, sizeof(*manager));
}

static struct vx_managed_path *
vx_path_manager_find(struct vx_path_manager *manager, const char *ifname,
                     union vmux_sockaddr *remote, unsigned int sock)
{
    for (unsigned int i = 0; i < manager->count; i++) {
        struct vx_managed_path *path = &manager->path[i];
        if (!strcmp(path->ifname, ifname) &&
            path->sock == sock &&
            vx_remote_equal(&path->remote, remote))
            return path;
    }
    return NULL;
}

static void
vx_path_manager_update_conf(struct vx_managed_path *path,
                            const struct vmux_path_conf *conf)
{
    if (conf->state == VMUX_UP) {
        path->desired_up = 1;
        path->desired_conf.state = VMUX_UP;
    } else if (conf->state == VMUX_DOWN) {
        path->desired_up = 0;
        path->desired_conf.state = VMUX_DOWN;
    }
    if (conf->pref)
        path->desired_conf.pref = conf->pref >> 1;
    if (conf->beat)
        path->desired_conf.beat = conf->beat * 1000;
    if (conf->fixed_rate)
        path->desired_conf.fixed_rate = conf->fixed_rate >> 1;
    if (conf->loss_limit)
        path->desired_conf.loss_limit = conf->loss_limit;
    if (conf->rtt_limit)
        path->desired_conf.rtt_limit = conf->rtt_limit;
    if (conf->tx_max_rate)
        path->desired_conf.tx_max_rate = conf->tx_max_rate;
    if (conf->rx_max_rate)
        path->desired_conf.rx_max_rate = conf->rx_max_rate;
    if (conf->mtu)
        path->desired_conf.mtu = conf->mtu;
    if (conf->monitor)
        path->desired_conf.monitor = 1;
    if (conf->probe_interval)
        path->desired_conf.probe_interval = conf->probe_interval;
    if (conf->probe_window)
        path->desired_conf.probe_window = conf->probe_window;
    if (conf->probe_recover)
        path->desired_conf.probe_recover = conf->probe_recover;
    path->config_dirty = 1;
}

static int
vx_path_manager_apply(struct vx_managed_path *path, struct vmux *vmux,
                      enum vmux_state state)
{
    struct vmux_path_conf conf = path->desired_conf;
    conf.local = path->bound_local;
    conf.remote = path->remote;
    conf.local_ifindex = path->bound_ifindex;
    conf.sock = path->sock;
    conf.state = state;
    conf.beat /= 1000;
    conf.pref = (unsigned char)((conf.pref << 1) | 1);
    conf.fixed_rate = (unsigned char)((conf.fixed_rate << 1) | 1);

    if (vmux_set_path(vmux, &conf))
        return -1;
    path->config_dirty = 0;
    return 0;
}

static int
vx_path_manager_suspend(struct vx_managed_path *path, struct vmux *vmux)
{
    if (!path->runtime_bound || !path->runtime_active)
        return 0;
    if (vx_path_manager_apply(path, vmux, VMUX_DOWN)) {
        if (errno != ENOENT)
            return -1;
        path->runtime_bound = 0;
    }
    path->runtime_active = 0;
    return 0;
}

static int
vx_path_manager_reconcile_one(struct vx_managed_path *path, struct vmux *vmux)
{
    struct vx_link_info info;
    int family = path->remote.sa.sa_family;
    int ret = vx_netlink_resolve(path->ifname, family,
                                 path->address_ready
                                    ? &path->current_local : NULL,
                                 &info);
    if (ret == -1)
        return -1;
    if (ret == 1)
        memset(&info, 0, sizeof(info));

    path->ifindex = info.ifindex;
    path->link_up = info.link_up;
    path->address_ready = info.address_ready;
    path->current_local = info.local;

    if (!path->desired_up || !path->link_up || !path->address_ready)
        return vx_path_manager_suspend(path, vmux);

    int binding_changed = path->runtime_bound &&
        (path->bound_ifindex != path->ifindex ||
         !vx_sockaddr_addr_equal(&path->bound_local, &path->current_local));

    if (binding_changed) {
        if (vmux_rebind_path(vmux, path->bound_ifindex, &path->remote,
                            path->ifindex, &path->current_local,
                            path->sock)) {
            if (errno != ENOENT)
                return -1;
            path->runtime_bound = 0;
        } else {
            path->bound_ifindex = path->ifindex;
            path->bound_local = path->current_local;
        }
    }
    if (!path->runtime_bound) {
        path->bound_ifindex = path->ifindex;
        path->bound_local = path->current_local;
        if (vx_path_manager_apply(path, vmux, VMUX_UP))
            return -1;
        path->runtime_bound = 1;
        path->runtime_active = 1;
        return 0;
    }
    if (!path->runtime_active || path->config_dirty || binding_changed) {
        if (vx_path_manager_apply(path, vmux, VMUX_UP)) {
            if (errno != ENOENT)
                return -1;
            path->runtime_bound = 0;
            path->bound_ifindex = path->ifindex;
            path->bound_local = path->current_local;
            if (vx_path_manager_apply(path, vmux, VMUX_UP))
                return -1;
            path->runtime_bound = 1;
        }
    }
    path->runtime_active = 1;
    return 0;
}

int
vx_path_manager_set(struct vx_path_manager *manager, struct vmux *vmux,
                    const char *ifname, unsigned int sock,
                    struct vmux_path_conf *conf)
{
    if (!manager || !vmux || !ifname || !ifname[0] || !conf ||
        !conf->remote.sa.sa_family) {
        errno = EINVAL;
        return -1;
    }
    struct vx_managed_path *path =
        vx_path_manager_find(manager, ifname, &conf->remote, sock);

    if (!path) {
        if (conf->state != VMUX_UP) {
            errno = ENOENT;
            return -1;
        }
        if (manager->count == manager->cap) {
            const unsigned int cap = manager->cap ? manager->cap * 2U : 64U;
            struct vx_managed_path *n = realloc(manager->path, cap * sizeof(*n));

            if (!n) {
                errno = ENOMEM;
                return -1;
            }
            manager->path = n;
            manager->cap = cap;
        }
        path = &manager->path[manager->count++];
        memset(path, 0, sizeof(*path));
        memcpy(path->ifname, ifname, strlen(ifname) + 1);
        path->remote = conf->remote;
        path->sock = sock;
        path->desired_conf.remote = conf->remote;
        path->desired_conf.sock = sock;
        path->desired_conf.beat = 100 * 1000;
        /* auto-adjusting by default, matching vmux_get_path()'s own default
         * in vmux.c (see its comment) -- was 1 (pinned), which combined
         * with tx_max_rate/rx_max_rate defaulting to 0 (uncapped) to
         * silently pin every via-interface path (the standard way to
         * bring one up, including every `connections N` sub-flow) at
         * zero throughput forever unless an operator explicitly gave a
         * `rate tx`, regardless of the vmux.c-level fix. vx_path_manager_
         * apply() re-encodes this into vmux_set_path()'s shifted CLI
         * convention on every reconcile, so it was overriding the vmux.c
         * default on every single path this manager ever touched. */
        path->desired_conf.fixed_rate = 0;
        path->desired_conf.loss_limit = 255;
    }
    vx_path_manager_update_conf(path, conf);
    if (vx_path_manager_reconcile_one(path, vmux))
        return -1;

    *conf = path->desired_conf;
    conf->local = path->current_local;
    conf->local_ifindex = path->ifindex;
    return 0;
}

int
vx_path_manager_reconcile(struct vx_path_manager *manager, struct vmux *vmux)
{
    for (unsigned int i = 0; i < manager->count; i++)
        if (vx_path_manager_reconcile_one(&manager->path[i], vmux))
            return -1;
    return 0;
}

unsigned int
vx_path_manager_status(struct vx_path_manager *manager, struct vmux *vmux,
                       const char *ifname, union vmux_sockaddr *remote,
                       struct vx_managed_status *status, unsigned int max)
{
    struct vmux_paths runtime = {0};
    if (vmux_get_paths(vmux, &runtime, NULL, NULL))
        return 0;

    unsigned int count = 0;
    for (unsigned int i = 0; i < manager->count && count < max; i++) {
        struct vx_managed_path *managed = &manager->path[i];
        if (ifname && ifname[0] && strcmp(ifname, managed->ifname))
            continue;
        if (!vx_remote_matches(remote, &managed->remote))
            continue;

        struct vx_managed_status *out = &status[count++];
        memset(out, 0, sizeof(*out));
        memcpy(out->ifname, managed->ifname, sizeof(out->ifname));
        out->ifindex = managed->ifindex;
        out->path.conf = managed->desired_conf;
        out->path.conf.remote = managed->remote;
        out->path.conf.local = managed->current_local;
        out->path.conf.local_ifindex = managed->ifindex;

        if (!managed->desired_up) {
            out->availability = VX_PATH_ADMIN_DOWN;
        } else if (!managed->link_up) {
            out->availability = VX_PATH_INTERFACE_DOWN;
        } else if (!managed->address_ready) {
            out->availability = VX_PATH_WAITING_ADDRESS;
        } else {
            out->availability = VX_PATH_AVAILABLE;
        }

        for (unsigned int k = 0; k < runtime.count; k++) {
            struct vmux_path *candidate = &runtime.path[k];
            if (!candidate->conf.local_ifindex ||
                candidate->conf.local_ifindex != managed->bound_ifindex ||
                candidate->conf.sock != managed->sock ||
                !vx_remote_equal(&candidate->conf.remote, &managed->remote))
                continue;
            out->path = *candidate;
            break;
        }
        if (!managed->address_ready) {
            memset(&out->path.conf.local, 0, sizeof(out->path.conf.local));
            out->path.conf.local_ifindex = managed->ifindex;
        }
    }
    return count;
}
