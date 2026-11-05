#include "common.h"
#include "ctl.h"
#include "hub.h"
#include "iface.h"
#include "ip.h"
#include "tun.h"
#include "argz.h"
#include "path_manager.h"

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/select.h>
#include <sodium.h>

/* Wire size 1400 minus the 22 bytes vmux adds (6 timestamp + 16 tag): what a
 * client gets when nobody has configured anything. */
#define VX_HUB_MTU_DEFAULT (1378U)

static int
vx_hub_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);

    if (fl == -1)
        return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ------------------------------------------------------------------------
 * Oversize packets: ICMP "fragmentation needed" / "packet too big".
 *
 * A client whose paths are configured with a small MTU must not drag the
 * tunnel MTU down for every other client. Instead the TUN stays at the
 * largest MTU any client can take, and a packet that is too large for the
 * one client it is addressed to is dropped and answered with the standard
 * path-MTU-discovery message, so the sender shrinks its packets for that
 * destination only. The message is injected back into the TUN as if it came
 * from the client (source = the packet's destination).
 * ------------------------------------------------------------------------ */

static uint32_t
vx_csum_add(uint32_t sum, const void *data, size_t len)
{
    const uint8_t *p = data;

    for (; len > 1; len -= 2, p += 2)
        sum += (uint32_t)((p[0] << 8) | p[1]);
    if (len)
        sum += (uint32_t)(p[0] << 8);
    return sum;
}

static uint16_t
vx_csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static void
vx_hub_oversize(int tun_fd, const void *pkt, size_t len, size_t mtu)
{
    const uint8_t *ip = pkt;
    uint8_t out[1280];

    if (len < 20)
        return;

    if ((ip[0] >> 4) == 4) {
        const size_t ihl = (size_t)(ip[0] & 0x0F) * 4;

        if (ihl < 20 || len < ihl || (ip[6] & 0x1F) || ip[7])
            return; /* malformed, or not the first fragment */

        /* never answer an ICMP error with an ICMP error */
        if (ip[9] == 1 && len > ihl && ip[ihl] != 0 && ip[ihl] != 8)
            return;

        const size_t quote = (len < ihl + 8) ? len : ihl + 8;
        const size_t total = 20 + 8 + quote;

        memset(out, 0, 28);
        out[0] = 0x45;
        out[1] = 0xC0;
        out[2] = (uint8_t)(total >> 8);
        out[3] = (uint8_t)total;
        out[8] = 64;
        out[9] = 1;
        memcpy(out + 12, ip + 16, 4); /* from the packet's destination */
        memcpy(out + 16, ip + 12, 4); /* to its sender */

        const uint16_t hc = vx_csum_fold(vx_csum_add(0, out, 20));

        out[10] = (uint8_t)(hc >> 8);
        out[11] = (uint8_t)hc;

        out[20] = 3; /* destination unreachable */
        out[21] = 4; /* fragmentation needed and DF set */
        out[26] = (uint8_t)(mtu >> 8);
        out[27] = (uint8_t)mtu;
        memcpy(out + 28, ip, quote);

        const uint16_t cc = vx_csum_fold(vx_csum_add(0, out + 20, total - 20));

        out[22] = (uint8_t)(cc >> 8);
        out[23] = (uint8_t)cc;

        tun_write(tun_fd, out, total);
    } else if ((ip[0] >> 4) == 6 && len >= 40) {
        if (ip[6] == 58 && len > 40 && ip[40] < 128)
            return; /* never answer an ICMPv6 error with an error */

        const size_t room = sizeof(out) - 48;
        const size_t quote = (len < room) ? len : room;
        const size_t plen = 8 + quote;
        const size_t total = 40 + plen;
        const uint32_t m = (mtu < 1280) ? 1280 : (uint32_t)mtu;

        memset(out, 0, 48);
        out[0] = 0x60;
        out[4] = (uint8_t)(plen >> 8);
        out[5] = (uint8_t)plen;
        out[6] = 58;
        out[7] = 64;
        memcpy(out + 8, ip + 24, 16);  /* from the packet's destination */
        memcpy(out + 24, ip + 8, 16);  /* to its sender */

        out[40] = 2; /* packet too big */
        out[44] = (uint8_t)(m >> 24);
        out[45] = (uint8_t)(m >> 16);
        out[46] = (uint8_t)(m >> 8);
        out[47] = (uint8_t)m;
        memcpy(out + 48, ip, quote);

        uint32_t sum = vx_csum_add(0, out + 8, 32);

        sum += (uint32_t)plen;
        sum += 58;
        sum = vx_csum_add(sum, out + 40, plen);

        const uint16_t cc = vx_csum_fold(sum);

        out[42] = (uint8_t)(cc >> 8);
        out[43] = (uint8_t)cc;

        tun_write(tun_fd, out, total);
    }
}

/* ------------------------------------------------------------------------ */

struct vx_hub_worker_arg {
    struct vmux_hub *hub;
    const int *tun_fds;
    unsigned int tun_fd_count;
    unsigned int worker_index;
    unsigned int worker_count;
};

static void *
vx_hub_worker_main(void *arg)
{
    struct vx_hub_worker_arg *a = arg;

    vmux_hub_worker_loop(a->hub, a->worker_index, a->worker_count,
                        a->tun_fds, a->tun_fd_count,
                        tun_read, vx_tun_write_validated, vx_hub_oversize,
                        &vx_quit);
    return NULL;
}

/* Sends one reply. The control socket is non-blocking and a Unix datagram
 * queue is short, so a long listing has to wait for the client to drain it
 * rather than silently losing rows. */
static void
vx_hub_send(int fd, const struct ctl_msg *res, const union ctl_sun *sun,
            socklen_t slen)
{
    for (int tries = 0; tries < 200; tries++) {
        if (sendto(fd, res, sizeof(*res), 0, &sun->sa, slen) != -1)
            return;

        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS) {
            perror("sendto(ctl)");
            return;
        }
        struct pollfd p = {.fd = fd, .events = POLLOUT};

        poll(&p, 1, 10);
    }
    vx_log("control reply dropped: client too slow\n");
}

/* Fills the reply for peer `name` (after an add/set). */
static void
vx_hub_fill_info(struct vmux_hub *hub, const char *name, struct ctl_peer *dst)
{
    const unsigned int n = vmux_hub_peer_count(hub);

    for (unsigned int i = 0; i < n; i++) {
        struct vmux_hub_peer_info info;

        if (vmux_hub_peer_info(hub, i, &info) || !info.active ||
            strcmp(info.name, name))
            continue;

        memset(dst, 0, sizeof(*dst));
        memcpy(dst->name, info.name, sizeof(dst->name));
        dst->info = info;
        return;
    }
}

int
vx_hub_peer_apply(struct vmux_hub *hub, int type, struct ctl_peer *p)
{
    switch (type) {
    case CTL_PEER_ADD: {
        unsigned char key[VMUX_PUBKEY_SIZE];

        if (vx_read_keyfile(key, p->keyfile))
            return EIO;

        const int r = vmux_hub_peer_add(hub, p->name, key, p->allowed,
                                       p->allowed_count, &p->policy);
        const int err = errno;

        sodium_memzero(key, sizeof(key));
        if (r)
            return err;

        struct vmux_conf conf = p->conf;

        if (vmux_hub_peer_set(hub, p->name, NULL, 0, 0, NULL, 0, &conf))
            return errno;
        return 0;
    }
    case CTL_PEER_SET: {
        struct vmux_conf conf = p->conf;

        if (vmux_hub_peer_set(hub, p->name, p->allowed, p->allowed_set,
                             p->allowed_count, &p->policy, p->unset, &conf))
            return errno;
        return 0;
    }
    case CTL_PEER_DEL:
        return vmux_hub_peer_del(hub, p->name) ? errno : 0;
    }
    return EINVAL;
}

static void
vx_hub_ctl(struct vmux_hub *hub, int ctl_fd, const char *tun_name, long pid,
           size_t mtu, int aes, const union vmux_sockaddr *local)
{
    static struct vmux_paths paths; /* housekeeping thread only */
    struct ctl_msg req, res = {.reply = 1};
    union ctl_sun sun;
    socklen_t slen = sizeof(sun);
    const ssize_t r = recvfrom(ctl_fd, &req, sizeof(req), 0, &sun.sa, &slen);

    if (r == -1) {
        if (errno != EAGAIN)
            perror("recvfrom(ctl)");
        return;
    }
    if (r != (ssize_t)sizeof(req))
        return;

    req.peer[sizeof(req.peer) - 1] = 0;
    res.type = req.type;
    memcpy(res.tun_name, tun_name, sizeof(res.tun_name));

    switch (req.type) {
    case CTL_NONE:
        break;
    case CTL_STATUS: {
        unsigned int active = 0;
        const unsigned int n = vmux_hub_peer_count(hub);

        for (unsigned int i = 0; i < n; i++) {
            struct vmux_hub_peer_info info;

            if (!vmux_hub_peer_info(hub, i, &info) && info.active)
                active++;
        }
        res.status.pid = pid;
        res.status.mtu = mtu;
        res.status.cipher = !aes;
        res.status.local = *local;
        res.status.hub = 1;
        res.status.peers = active;
        vmux_hub_get_stats(hub, &res.status.hubstats);
        break;
    }
    case CTL_CONF: {
        if (req.peer[0]) {
            struct vmux *m = vmux_hub_peer_get(hub, req.peer);

            if (!m) {
                res.ret = ENOENT;
                break;
            }
            if (vmux_set(m, &req.conf))
                res.ret = errno;
            res.conf = req.conf;
            break;
        }
        /* No peer named: these become the defaults for clients added later
         * and are applied to every existing client too -- an explicit
         * `peer set` is how a single client is made different. */
        struct vmux_conf defaults = req.conf;

        vmux_hub_set_defaults(hub, &defaults);

        const unsigned int n = vmux_hub_peer_count(hub);

        for (unsigned int i = 0; i < n; i++) {
            struct vmux_hub_peer_info info;

            if (vmux_hub_peer_info(hub, i, &info) || !info.active)
                continue;

            struct vmux *m = vmux_hub_peer_get(hub, info.name);
            struct vmux_conf c = req.conf;

            if (m)
                vmux_set(m, &c);
        }
        res.conf = defaults;
        break;
    }
    case CTL_PATH_STATUS: {
        const unsigned int n = vmux_hub_peer_count(hub);

        res.ret = EAGAIN;
        res.connections = 0;
        for (unsigned int i = 0; i < n; i++) {
            struct vmux_hub_peer_info info;

            if (vmux_hub_peer_info(hub, i, &info) || !info.active)
                continue;
            if (req.peer[0] && strcmp(req.peer, info.name))
                continue;

            struct vmux *m = vmux_hub_peer_get(hub, info.name);

            if (!m || vmux_get_paths(m, &paths, &req.path.conf.local,
                                    &req.path.conf.remote))
                continue;
            res.connections += paths.total;

            for (unsigned int k = 0; k < paths.count; k++) {
                memset(res.ifname, 0, sizeof(res.ifname));
                memcpy(res.peer, info.name, sizeof(res.peer));
                res.ifindex = 0;
                res.path_availability = VX_PATH_AVAILABLE;
                res.path = paths.path[k];
                vx_hub_send(ctl_fd, &res, &sun, slen);
            }
        }
        memset(&res.path, 0, sizeof(res.path));
        memset(res.peer, 0, sizeof(res.peer));
        res.ret = 0;
        break;
    }
    case CTL_PATH_CONF:
        /* A client's paths are created by the client and mirrored here; a
         * client is tuned with `peer set`, which is enforced no matter what
         * the client advertises. */
        res.ret = ENOTSUP;
        break;
    case CTL_ERRORS: {
        if (req.peer[0]) {
            struct vmux *m = vmux_hub_peer_get(hub, req.peer);

            if (!m)
                res.ret = ENOENT;
            else if (vmux_get_errors(m, &res.errors))
                res.ret = errno;
            break;
        }
        /* all clients together: sum the counts, keep the latest source */
        struct vmux_errors sum;
        const unsigned int n = vmux_hub_peer_count(hub);

        memset(&sum, 0, sizeof(sum));
        for (unsigned int i = 0; i < n; i++) {
            struct vmux_hub_peer_info info;
            struct vmux_errors e;

            if (vmux_hub_peer_info(hub, i, &info) || !info.active)
                continue;

            struct vmux *m = vmux_hub_peer_get(hub, info.name);

            if (!m || vmux_get_errors(m, &e))
                continue;

#define VX_MERGE(F) do { \
    if (e.F.count) { \
        if (e.F.time >= sum.F.time) { \
            sum.F.addr = e.F.addr; \
            sum.F.time = e.F.time; \
        } \
        sum.F.count += e.F.count; \
    } \
} while (0)
            VX_MERGE(decrypt);
            VX_MERGE(clocksync);
            VX_MERGE(keyx);
#undef VX_MERGE
        }
        res.errors = sum;
        break;
    }
    case CTL_PEER_ADD:
    case CTL_PEER_SET:
    case CTL_PEER_DEL: {
        struct ctl_peer spec = req.peer_spec;

        spec.name[sizeof(spec.name) - 1] = 0;
        spec.keyfile[sizeof(spec.keyfile) - 1] = 0;

        if (spec.allowed_count > VMUX_HUB_ALLOWED_MAX) {
            res.ret = EINVAL;
            break;
        }
        res.ret = vx_hub_peer_apply(hub, (int)req.type, &spec);
        memset(&res.peer_spec, 0, sizeof(res.peer_spec));
        if (!res.ret && req.type != CTL_PEER_DEL)
            vx_hub_fill_info(hub, spec.name, &res.peer_spec);
        break;
    }
    case CTL_PEER_LIST: {
        const unsigned int n = vmux_hub_peer_count(hub);

        res.ret = EAGAIN;
        for (unsigned int i = 0; i < n; i++) {
            struct vmux_hub_peer_info info;

            if (vmux_hub_peer_info(hub, i, &info) || !info.active)
                continue;
            if (req.peer[0] && strcmp(req.peer, info.name))
                continue;

            memset(&res.peer_spec, 0, sizeof(res.peer_spec));
            memcpy(res.peer_spec.name, info.name, sizeof(res.peer_spec.name));
            res.peer_spec.info = info;
            vx_hub_send(ctl_fd, &res, &sun, slen);
        }
        memset(&res.peer_spec, 0, sizeof(res.peer_spec));
        res.ret = 0;
        break;
    }
    }
    vx_hub_send(ctl_fd, &res, &sun, slen);
}

int
vx_hub_run(const struct vx_hub_args *a)
{
    struct vx_argz_addr local = a->local;
    int aes = !a->chacha;
    struct vmux_hub *hub = vmux_hub_create(&local.sock, &aes);

    if (!hub) {
        vx_log("couldn't create hub\n");
        return -1;
    }
    if (!a->chacha && !aes)
        vx_log("AES is not available, enjoy ChaCha20!\n");

    char tun_name[64];
    int tun_multiqueue = 0;
    const int tun_fd = tun_create(tun_name, sizeof(tun_name), a->dev,
                                  &tun_multiqueue);

    if (tun_fd == -1) {
        vx_log("couldn't create tun device\n");
        vmux_hub_delete(hub);
        return -1;
    }
    if (a->qlen_set && iface_set_qlen(tun_name, a->qlen) == -1)
        vx_log("couldn't setup qlen at %llu on device %s\n", a->qlen, tun_name);

    size_t mtu = a->mtu ? (size_t)a->mtu : VX_HUB_MTU_DEFAULT;

    if (iface_set_mtu(tun_name, mtu) == -1)
        vx_log("couldn't setup MTU at %zu on device %s\n", mtu, tun_name);

    if (tun_set_persist(tun_fd, a->persist) == -1)
        vx_log("couldn't %sable persist mode on device %s\n",
               a->persist ? "en" : "dis", tun_name);

    const int ctl_fd = ctl_create(tun_name);

    if (ctl_fd == -1) {
        vx_log("couldn't create the control socket for %s: %s\n",
               tun_name, strerror(errno));
        vmux_hub_delete(hub);
        return -1;
    }
    if (vx_hub_nonblock(tun_fd) || vx_hub_nonblock(ctl_fd)) {
        vx_log("couldn't setup non-blocking fds\n");
        vmux_hub_delete(hub);
        return -1;
    }
    if (a->peers_file && vx_peers_load(hub, a->peers_file)) {
        vmux_hub_delete(hub);
        ctl_delete(ctl_fd);
        return -1;
    }
    const long pid = (long)getpid();

    vx_log("running on device %s as pid %li (multi-client)\n", tun_name, pid);

    const unsigned int worker_count = vmux_worker_count();
    pthread_t *workers = malloc(worker_count * sizeof(pthread_t));
    struct vx_hub_worker_arg *worker_args =
        malloc(worker_count * sizeof(struct vx_hub_worker_arg));
    int *worker_tun_fd = malloc(worker_count * sizeof(int));
    unsigned int workers_started = 0;

    if (!workers || !worker_args || !worker_tun_fd) {
        vx_log("couldn't allocate worker thread table\n");
        free(workers);
        free(worker_args);
        free(worker_tun_fd);
        vmux_hub_delete(hub);
        return -1;
    }
    /* One TUN queue per worker where supported, every worker polling every
     * queue -- see the same logic and its rationale in vx_bind(). */
    worker_tun_fd[0] = tun_fd;

    int queues_ok = 1;

    if (tun_multiqueue) {
        for (unsigned int i = 1; i < worker_count; i++) {
            worker_tun_fd[i] = tun_create_queue(tun_name);
            if (worker_tun_fd[i] == -1 || vx_hub_nonblock(worker_tun_fd[i])) {
                vx_log("couldn't open tun queue %u: %s\n", i, strerror(errno));
                queues_ok = 0;
                break;
            }
        }
    } else {
        queues_ok = 0;
    }
    unsigned int tun_fd_count;

    if (!queues_ok) {
        for (unsigned int i = 1; i < worker_count; i++) {
            if (worker_tun_fd[i] > 0 && worker_tun_fd[i] != tun_fd)
                close(worker_tun_fd[i]);
            worker_tun_fd[i] = tun_fd;
        }
        tun_fd_count = 1;
    } else {
        tun_fd_count = worker_count;
        if (worker_count > 1)
            vx_log("opened %u independent tun queues, shared by every "
                   "worker\n", worker_count);
    }
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1 << 20);

    for (unsigned int i = 0; i < worker_count; i++) {
        worker_args[i] = (struct vx_hub_worker_arg){
            .hub = hub,
            .tun_fds = worker_tun_fd,
            .tun_fd_count = tun_fd_count,
            .worker_index = i,
            .worker_count = worker_count,
        };
        if (pthread_create(&workers[i], &attr, vx_hub_worker_main,
                           &worker_args[i])) {
            vx_log("couldn't start worker thread %u: %s\n", i, strerror(errno));
            break;
        }
        workers_started++;
    }
    pthread_attr_destroy(&attr);

    if (!workers_started) {
        vx_log("no worker threads could be started\n");
        vmux_hub_delete(hub);
        free(workers);
        free(worker_args);
        free(worker_tun_fd);
        return -1;
    }
    if (workers_started < worker_count)
        vx_log("only %u of %u worker threads started, continuing\n",
               workers_started, worker_count);

    fd_set rfds;

    FD_ZERO(&rfds);

    while (!vx_quit) {
        FD_SET(ctl_fd, &rfds);

        vmux_hub_update(hub);

        struct timeval tv = {.tv_usec = 100000};
        const int ret = select(ctl_fd + 1, &rfds, NULL, NULL, &tv);

        if (ret == -1) {
            if (errno == EBADF) {
                perror("select");
                break;
            }
            continue;
        }
        /* The tunnel MTU follows the largest client unless pinned with
         * `bind mtu`; a client that can take less is answered per packet. */
        if (!a->mtu) {
            const size_t m = vmux_hub_get_mtu(hub);

            if (m && m != mtu) {
                if (iface_set_mtu(tun_name, m) == -1)
                    vx_log("couldn't setup MTU at %zu on device %s\n",
                           m, tun_name);
                mtu = m;
            }
        }
        if (FD_ISSET(ctl_fd, &rfds))
            vx_hub_ctl(hub, ctl_fd, tun_name, pid, mtu, aes, &local.sock);
    }
    if (vx_reload && tun_fd >= 0)
        tun_set_persist(tun_fd, 1);

    for (unsigned int i = 0; i < workers_started; i++)
        pthread_join(workers[i], NULL);
    for (unsigned int i = 1; i < worker_count; i++)
        if (worker_tun_fd[i] != tun_fd)
            close(worker_tun_fd[i]);

    free(workers);
    free(worker_args);
    free(worker_tun_fd);

    vmux_hub_delete(hub);
    ctl_delete(ctl_fd);
    return 0;
}
