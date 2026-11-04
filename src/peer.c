#include "common.h"
#include "ctl.h"
#include "hub.h"
#include "argz.h"

#include <limits.h>
#include <stdlib.h>

/* ------------------------------------------------------------------------
 * Parsing
 * ------------------------------------------------------------------------ */

static int
vx_parse_prefix(const char *s, struct vmux_prefix *p)
{
    char buf[64];
    const char *slash = strchr(s, '/');
    const size_t n = slash ? (size_t)(slash - s) : strlen(s);

    if (!n || n >= sizeof(buf))
        return -1;

    memcpy(buf, s, n);
    buf[n] = 0;

    memset(p, 0, sizeof(*p));

    unsigned int max;
    struct in_addr a4;
    struct in6_addr a6;

    if (inet_pton(AF_INET, buf, &a4) == 1) {
        p->family = AF_INET;
        memcpy(p->addr, &a4, sizeof(a4));
        max = 32;
    } else if (inet_pton(AF_INET6, buf, &a6) == 1) {
        p->family = AF_INET6;
        memcpy(p->addr, &a6, sizeof(a6));
        max = 128;
    } else {
        return -1;
    }
    unsigned long len = max;

    if (slash) {
        char *end = NULL;

        if (!slash[1])
            return -1;
        len = strtoul(slash + 1, &end, 10);
        if (*end || len > max)
            return -1;
    }
    p->len = (unsigned char)len;
    return 0;
}

void
vx_peer_format_prefix(char *dst, size_t size, const struct vmux_prefix *p)
{
    char addr[INET6_ADDRSTRLEN] = "?";

    if (p->family == AF_INET)
        inet_ntop(AF_INET, p->addr, addr, sizeof(addr));
    else if (p->family == AF_INET6)
        inet_ntop(AF_INET6, p->addr, addr, sizeof(addr));

    snprintf(dst, size, "%s/%u", addr, (unsigned)p->len);
}

/* allowed ADDR/LEN[,ADDR/LEN...] */
static int
vx_peer_allowed(int argc, char **argv, void *data)
{
    struct ctl_peer *peer = data;

    if (argz_help_me(argc, argv)) {
        for (unsigned int i = 0; i < peer->allowed_count; i++) {
            char tmp[64];

            vx_peer_format_prefix(tmp, sizeof(tmp), &peer->allowed[i]);
            printf("%s%s", i ? "," : "", tmp);
        }
        if (peer->allowed_count)
            printf("\n");
    } else if (argc > 1) {
        char *list = strdup(argv[1]);
        char *save = NULL;

        if (!list)
            return -1;

        peer->allowed_count = 0;
        for (char *tok = strtok_r(list, ",", &save); tok;
             tok = strtok_r(NULL, ",", &save)) {
            if (peer->allowed_count >= VMUX_HUB_ALLOWED_MAX) {
                vx_log("Option %s takes at most %u addresses\n",
                       argv[0], VMUX_HUB_ALLOWED_MAX);
                free(list);
                return -1;
            }
            if (vx_parse_prefix(tok, &peer->allowed[peer->allowed_count])) {
                vx_log("Option %s: '%s' is not an ADDRESS[/LENGTH]\n",
                       argv[0], tok);
                free(list);
                return -1;
            }
            peer->allowed_count++;
        }
        free(list);
        if (!peer->allowed_count) {
            vx_log("Option %s requires at least one address\n", argv[0]);
            return -1;
        }
        peer->allowed_set = 1;
        return argc - 2;
    } else {
        vx_log("Option %s requires an address list\n", argv[0]);
    }
    return -1;
}

static int
vx_peer_unset_bits(const char *list, unsigned int *bits)
{
    static const struct {
        const char *name;
        unsigned int bit;
    } map[] = {
        {"tx",        VMUX_POLICY_TX_RATE},
        {"rx",        VMUX_POLICY_RX_RATE},
        {"mtu",       VMUX_POLICY_MTU},
        {"pref",      VMUX_POLICY_PREF},
        {"losslimit", VMUX_POLICY_LOSSLIMIT},
        {"rttlimit",  VMUX_POLICY_RTTLIMIT},
        {"maxpaths",  VMUX_POLICY_MAXPATHS},
    };
    char *copy = strdup(list);
    char *save = NULL;

    if (!copy)
        return -1;

    *bits = 0;
    for (char *tok = strtok_r(copy, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        unsigned int k;

        for (k = 0; k < COUNT(map); k++) {
            if (!strcmp(tok, map[k].name)) {
                *bits |= map[k].bit;
                break;
            }
        }
        if (k == COUNT(map)) {
            vx_log("Option unset: unknown setting '%s' (use tx, rx, mtu, "
                   "pref, losslimit, rttlimit, maxpaths)\n", tok);
            free(copy);
            return -1;
        }
    }
    free(copy);
    return 0;
}

/* argv[0] is the client's name; everything after it is options. */
int
vx_peer_parse(int argc, char **argv, int set, struct ctl_peer *out,
              const char **dev)
{
    memset(out, 0, sizeof(*out));

    if (argc < 1 || !argv[0] || !argv[0][0] || !strcmp(argv[0], "help")) {
        vx_log("a client name is required\n");
        return -1;
    }
    if (strlen(argv[0]) >= sizeof(out->name)) {
        vx_log("client name '%s' is too long (max %u)\n",
               argv[0], VMUX_HUB_NAME_MAX - 1);
        return -1;
    }
    memcpy(out->name, argv[0], strlen(argv[0]) + 1);

    struct argz_ull tx = {.suffix = argz_size_suffix};
    struct argz_ull rx = {.suffix = argz_size_suffix};
    struct argz_ull mtu = {.max = VMUX_MTU_HARD_MAX};
    struct argz_ull pref = {.max = 0x7F};
    struct argz_ull loss = {.max = 100, .suffix = vx_argz_percent_suffix};
    struct argz_ull rtt = {.suffix = argz_time_suffix};
    struct argz_ull maxpaths = {.min = 1, .max = VMUX_PATH_MAX};
    struct argz_ull kx = {.suffix = argz_time_suffix};
    struct argz_ull tt = {.suffix = argz_time_suffix};
    struct argz_ull ka = {.suffix = argz_time_suffix};
    struct argz_ull rw = {.suffix = argz_time_suffix};
    int strict = 0;
    struct argz_path key = {0};
    const char *unset = NULL;
    const char *dev_dummy = NULL;

    struct argz ratez[] = {
        {"tx", "Maximum rate we send to this client", argz_ull, &tx},
        {"rx", "Maximum rate this client may send us", argz_ull, &rx},
        {0}};

    struct argz z[] = {
        {"dev",      "Tunnel device",                 vx_argz_dev,
                                                       dev ? dev : &dev_dummy},
        {"key",      "Key file of this client (add only)", argz_path, &key},
        {"allowed",  "Inner addresses this client owns, e.g. "
                     "10.77.0.2/32,fd00::2/128",       vx_peer_allowed, out},
        {"rate",     "Rate limits enforced for this client", argz, &ratez},
        {"mtu",      "Fixed wire size for this client's paths", argz_ull, &mtu},
        {"pref",     "Path preference for this client", argz_ull, &pref},
        {"losslimit", "Loss limit for this client",   argz_ull, &loss},
        {"rttlimit", "RTT limit for this client",     argz_ull, &rtt},
        {"maxpaths", "Most paths this client may hold", argz_ull, &maxpaths},
        {"kxtimeout",     "Key rotation timeout",     argz_ull, &kx},
        {"timetolerance", "Clock sync tolerance",     argz_ull, &tt},
        {"keepalive",     "Keep alive timeout",       argz_ull, &ka},
        {"reorderwindow", "Longest wait for a missing packet", argz_ull, &rw},
        {"strictorder",   "Number packets (TCP too) and release them in "
                          "order: on|off",                vx_argz_onoff, &strict},
        {"unset",    "Stop enforcing: tx,rx,mtu,pref,losslimit,rttlimit,"
                     "maxpaths (set only)",           argz_str, &unset},
        {0}};

    const int err = argz(argc, argv, z);

    if (err) {
        if (err > 0)
            vx_log("Option %s is unknown\n", argv[argc - err]);
        return -1;
    }
    if (argz_is_set(ratez, "tx")) {
        if (!tx.value) {
            vx_log("Option tx must be greater than zero (use unset tx to "
                   "remove the limit)\n");
            return -1;
        }
        out->policy.set |= VMUX_POLICY_TX_RATE;
        out->policy.tx_max_rate = tx.value;
    }
    if (argz_is_set(ratez, "rx")) {
        if (!rx.value) {
            vx_log("Option rx must be greater than zero (use unset rx to "
                   "remove the limit)\n");
            return -1;
        }
        out->policy.set |= VMUX_POLICY_RX_RATE;
        out->policy.rx_max_rate = rx.value;
    }
    if (argz_is_set(z, "mtu")) {
        if (!mtu.value) {
            vx_log("Option mtu must be greater than zero (use unset mtu)\n");
            return -1;
        }
        out->policy.set |= VMUX_POLICY_MTU;
        out->policy.mtu = mtu.value;
    }
    if (argz_is_set(z, "pref")) {
        out->policy.set |= VMUX_POLICY_PREF;
        out->policy.pref = (unsigned char)pref.value;
    }
    if (argz_is_set(z, "losslimit")) {
        out->policy.set |= VMUX_POLICY_LOSSLIMIT;
        out->policy.loss_limit = (unsigned char)(loss.value * 255 / 100);
    }
    if (argz_is_set(z, "rttlimit")) {
        if (!rtt.value) {
            vx_log("Option rttlimit must be greater than zero (use unset "
                   "rttlimit)\n");
            return -1;
        }
        out->policy.set |= VMUX_POLICY_RTTLIMIT;
        out->policy.rtt_limit = rtt.value * UINT64_C(1000);
    }
    if (argz_is_set(z, "maxpaths")) {
        out->policy.set |= VMUX_POLICY_MAXPATHS;
        out->policy.max_paths = (unsigned int)maxpaths.value;
    }
    out->conf.kxtimeout     = kx.value * UINT64_C(1000);
    out->conf.timetolerance = tt.value * UINT64_C(1000);
    out->conf.keepalive     = ka.value * UINT64_C(1000);
    /* same "explicit 0 turns it off" marker as `set reorderwindow` */
    out->conf.reorder_window = argz_is_set(z, "reorderwindow")
                             ? ((rw.value * UINT64_C(1000)) << 1) | 1 : 0;
    out->conf.strict_order = (uint64_t)strict;

    if (unset) {
        if (!set) {
            vx_log("Option unset only applies to 'peer set'\n");
            return -1;
        }
        if (vx_peer_unset_bits(unset, &out->unset))
            return -1;
        if (out->unset & out->policy.set) {
            vx_log("a setting cannot be both set and unset in one command\n");
            return -1;
        }
    }
    if (set) {
        if (key.path) {
            vx_log("a client's key cannot be changed: 'peer del' it and add "
                   "it again\n");
            return -1;
        }
        return 0;
    }
    if (!key.path) {
        vx_log("a key file is needed (key FILE)\n");
        return -1;
    }
    if (!out->allowed_count) {
        vx_log("at least one allowed address is needed (allowed ADDR/LEN)\n");
        return -1;
    }
    char resolved[PATH_MAX];

    if (!realpath(key.path, resolved)) {
        vx_log("couldn't open %s: %s\n", key.path, strerror(errno));
        return -1;
    }
    if (strlen(resolved) >= sizeof(out->keyfile)) {
        vx_log("key file path is too long\n");
        return -1;
    }
    memcpy(out->keyfile, resolved, strlen(resolved) + 1);
    return 0;
}

/* ------------------------------------------------------------------------
 * Peers file: one client per line, the same words `peer add` takes after
 * the subcommand:   NAME key FILE allowed ADDR/LEN[,...] [rate tx X rx Y] ...
 * Blank lines and lines starting with # are ignored.
 * ------------------------------------------------------------------------ */

int
vx_peers_load(struct vmux_hub *hub, const char *file)
{
    FILE *f = fopen(file, "r");

    if (!f) {
        vx_log("couldn't open peers file %s: %s\n", file, strerror(errno));
        return -1;
    }
    char line[2048];
    unsigned int lineno = 0, loaded = 0;
    int ret = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        if (!strchr(line, '\n') && !feof(f)) {
            vx_log("%s:%u: line too long\n", file, lineno);
            ret = -1;
            break;
        }
        char *words[64];
        int n = 0;
        char *save = NULL;

        for (char *tok = strtok_r(line, " \t\r\n", &save);
             tok && n < (int)COUNT(words) - 1;
             tok = strtok_r(NULL, " \t\r\n", &save)) {
            if (tok[0] == '#')
                break;
            words[n++] = tok;
        }
        if (!n)
            continue;

        words[n] = NULL;

        struct ctl_peer peer;

        if (vx_peer_parse(n, words, 0, &peer, NULL)) {
            vx_log("%s:%u: invalid client definition\n", file, lineno);
            ret = -1;
            break;
        }
        const int err = vx_hub_peer_apply(hub, CTL_PEER_ADD, &peer);

        if (err) {
            vx_log("%s:%u: couldn't add client %s: %s\n", file, lineno,
                   peer.name, strerror(err));
            ret = -1;
            break;
        }
        loaded++;
    }
    fclose(f);
    if (!ret)
        vx_log("loaded %u client(s) from %s\n", loaded, file);
    return ret;
}

/* ------------------------------------------------------------------------
 * Output
 * ------------------------------------------------------------------------ */

static void
vx_peer_rate(char *dst, size_t size, const struct vmux_policy *p,
             unsigned int bit, uint64_t bytes)
{
    if (!(p->set & bit) || vx_torate(dst, size, bytes * 8))
        snprintf(dst, size, "client");
}

static void
vx_peer_allowed_str(char *dst, size_t size, const struct vmux_hub_peer_info *i)
{
    dst[0] = 0;
    for (unsigned int k = 0; k < i->allowed_count; k++) {
        char tmp[64];
        size_t len = strlen(dst);

        vx_peer_format_prefix(tmp, sizeof(tmp), &i->allowed[k]);
        snprintf(dst + len, size - len, "%s%s", k ? "," : "", tmp);
    }
    if (!dst[0])
        snprintf(dst, size, "-");
}

/* One line, same style as the `path` and `set` confirmations. */
static void
vx_peer_print_conf(const char *tun, const struct vmux_hub_peer_info *i)
{
    const struct vmux_policy *p = &i->policy;
    char allowed[512], tx[32], rx[32], mtu[16] = "client", pref[16] = "client";
    char loss[16] = "client", rtt[32] = "client", maxp[16] = "any";
    char kx[32], tt[32], ka[32], rw[32];

    vx_peer_allowed_str(allowed, sizeof(allowed), i);
    vx_peer_rate(tx, sizeof(tx), p, VMUX_POLICY_TX_RATE, p->tx_max_rate);
    vx_peer_rate(rx, sizeof(rx), p, VMUX_POLICY_RX_RATE, p->rx_max_rate);

    if (p->set & VMUX_POLICY_MTU)
        snprintf(mtu, sizeof(mtu), "%" PRIu64, p->mtu);
    if (p->set & VMUX_POLICY_PREF)
        snprintf(pref, sizeof(pref), "%u", (unsigned)p->pref);
    if (p->set & VMUX_POLICY_LOSSLIMIT)
        snprintf(loss, sizeof(loss), "%u%%", (unsigned)p->loss_limit * 100U / 255U);
    if ((p->set & VMUX_POLICY_RTTLIMIT) &&
        vx_totime(rtt, sizeof(rtt), p->rtt_limit / 1000))
        snprintf(rtt, sizeof(rtt), "client");
    if (p->set & VMUX_POLICY_MAXPATHS)
        snprintf(maxp, sizeof(maxp), "%u", p->max_paths);

    vx_totime(kx, sizeof(kx), i->conf.kxtimeout / 1000);
    vx_totime(tt, sizeof(tt), i->conf.timetolerance / 1000);
    vx_totime(ka, sizeof(ka), i->conf.keepalive / 1000);
    vx_totime(rw, sizeof(rw), i->conf.reorder_window / 1000);

    printf("peer dev %s name %s allowed %s rate tx %s rx %s mtu %s pref %s "
           "losslimit %s rttlimit %s maxpaths %s kxtimeout %s "
           "timetolerance %s keepalive %s reorderwindow %s strictorder %s\n",
           tun, i->name, allowed, tx, rx, mtu, pref, loss, rtt, maxp,
           kx, tt, ka, rw, i->conf.strict_order ? "on" : "off");
}

static void
vx_peer_print_detail(const char *tun, const struct vmux_hub_peer_info *i)
{
    const struct vmux_policy *p = &i->policy;
    char allowed[512], tx[32], rx[32], buf[32];

    vx_peer_allowed_str(allowed, sizeof(allowed), i);
    vx_peer_rate(tx, sizeof(tx), p, VMUX_POLICY_TX_RATE, p->tx_max_rate);
    vx_peer_rate(rx, sizeof(rx), p, VMUX_POLICY_RX_RATE, p->rx_max_rate);

    printf("peer      %s\n", i->name);
    printf("tunnel    %s\n", tun);
    printf("allowed   %s\n", allowed);
    printf("paths     %u\n", i->path_count);
    printf("mtu       %zu\n", i->mtu);
    printf("enforced  tx %s  rx %s", tx, rx);

    if (p->set & VMUX_POLICY_MTU)
        printf("  mtu %" PRIu64, p->mtu);
    if (p->set & VMUX_POLICY_PREF)
        printf("  pref %u", (unsigned)p->pref);
    if (p->set & VMUX_POLICY_LOSSLIMIT)
        printf("  losslimit %u%%", (unsigned)p->loss_limit * 100U / 255U);
    if ((p->set & VMUX_POLICY_RTTLIMIT) &&
        !vx_totime(buf, sizeof(buf), p->rtt_limit / 1000))
        printf("  rttlimit %s", buf);
    if (p->set & VMUX_POLICY_MAXPATHS)
        printf("  maxpaths %u", p->max_paths);
    printf("\n");

    vx_totime(buf, sizeof(buf), i->conf.kxtimeout / 1000);
    printf("kxtimeout %s", buf);
    vx_totime(buf, sizeof(buf), i->conf.timetolerance / 1000);
    printf("  timetolerance %s", buf);
    vx_totime(buf, sizeof(buf), i->conf.keepalive / 1000);
    printf("  keepalive %s", buf);
    vx_totime(buf, sizeof(buf), i->conf.reorder_window / 1000);
    printf("  reorderwindow %s", buf);
    printf("  strictorder %s\n", i->conf.strict_order ? "on" : "off");
    printf("dropped   tx-rate %" PRIu64 "  rx-rate %" PRIu64 "  mtu %" PRIu64
           "  spoofed %" PRIu64 "\n",
           i->tx_drop_rate, i->rx_drop_rate, i->tx_drop_mtu, i->rx_drop_spoof);
}

static void
vx_peer_print_row(const struct vmux_hub_peer_info *i)
{
    const struct vmux_policy *p = &i->policy;
    char allowed[512], tx[32], rx[32];

    vx_peer_allowed_str(allowed, sizeof(allowed), i);
    vx_peer_rate(tx, sizeof(tx), p, VMUX_POLICY_TX_RATE, p->tx_max_rate);
    vx_peer_rate(rx, sizeof(rx), p, VMUX_POLICY_RX_RATE, p->rx_max_rate);

    printf("%-16s %-5u %-6zu %-10s %-10s %-" "28s" " %" PRIu64 "/%" PRIu64
           "/%" PRIu64 "/%" PRIu64 "\n",
           i->name, i->path_count, i->mtu, tx, rx, allowed,
           i->tx_drop_rate, i->rx_drop_rate, i->tx_drop_mtu, i->rx_drop_spoof);
}

/* ------------------------------------------------------------------------
 * Command
 * ------------------------------------------------------------------------ */

static void
vx_peer_usage(void)
{
    printf("  %-14s  %s\n", "peer add",  "NAME key FILE allowed ADDR/LEN[,...] "
                                          "[rate tx X rx Y] [mtu N] [pref N] ...");
    printf("  %-14s  %s\n", "peer set",  "NAME [allowed ...] [rate ...] "
                                          "[unset tx,rx,...] ...");
    printf("  %-14s  %s\n", "peer del",  "NAME");
    printf("  %-14s  %s\n", "peer list", "List clients of a multi-client tunnel");
    printf("  %-14s  %s\n", "peer show", "NAME   Show one client in detail");
}

int
vx_peer(int argc, char **argv, void *data)
{
    if (argc < 2 || !strcmp(argv[1], "help")) {
        vx_peer_usage();
        return argc < 2 ? -1 : 0;
    }
    const char *sub = argv[1];
    const char *dev = NULL;
    struct ctl_msg req = {0}, res = {0};
    int is_list = 0, detail = 0;

    if (!strcmp(sub, "list")) {
        struct argz z[] = {
            {"dev", "Tunnel device", vx_argz_dev, &dev},
            {0}};
        int err = argz(argc - 1, argv + 1, z);

        if (err) {
            if (err > 0)
                vx_log("Option %s is unknown\n", argv[argc - err]);
            return -1;
        }
        req.type = CTL_PEER_LIST;
        is_list = 1;
    } else if (!strcmp(sub, "add") || !strcmp(sub, "set")) {
        struct ctl_peer spec;

        if (vx_peer_parse(argc - 2, argv + 2, !strcmp(sub, "set"), &spec, &dev))
            return -1;

        req.type = !strcmp(sub, "set") ? CTL_PEER_SET : CTL_PEER_ADD;
        req.peer_spec = spec;
    } else if (!strcmp(sub, "del") || !strcmp(sub, "show")) {
        if (argc < 3) {
            vx_log("a client name is required\n");
            return -1;
        }
        if (strlen(argv[2]) >= sizeof(req.peer)) {
            vx_log("client name '%s' is too long\n", argv[2]);
            return -1;
        }
        struct argz z[] = {
            {"dev", "Tunnel device", vx_argz_dev, &dev},
            {0}};
        int err = argz(argc - 2, argv + 2, z);

        if (err) {
            if (err > 0)
                vx_log("Option %s is unknown\n", argv[argc - err]);
            return -1;
        }
        if (!strcmp(sub, "del")) {
            req.type = CTL_PEER_DEL;
            memcpy(req.peer_spec.name, argv[2], strlen(argv[2]) + 1);
        } else {
            req.type = CTL_PEER_LIST;
            memcpy(req.peer, argv[2], strlen(argv[2]) + 1);
            is_list = 1;
            detail = 1;
        }
    } else {
        vx_log("Option %s is unknown\n", sub);
        vx_peer_usage();
        return -1;
    }
    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return -1;
    }
    int ret = 0;

    if (!is_list) {
        ret = ctl_reply(fd, &res, &req);

        if (!ret) {
            if (req.type == CTL_PEER_DEL)
                printf("peer dev %s name %s removed\n", res.tun_name,
                       req.peer_spec.name);
            else
                vx_peer_print_conf(res.tun_name, &res.peer_spec.info);
        } else if (errno == ENOTSUP || errno == ENOENT) {
            vx_log("%s\n", errno == ENOENT
                   ? "no such client (or this is not a multi-client tunnel)"
                   : "not supported by this tunnel");
        }
    } else {
        if (send(fd, &req, sizeof(req), 0) != sizeof(req))
            ret = -1;

        unsigned int count = 0;

        while (!ret) {
            if (recv(fd, &res, sizeof(res), 0) == -1) {
                ret = -1;
                break;
            }
            if (res.type != CTL_PEER_LIST) {
                errno = EBADMSG;
                ret = -1;
                break;
            }
            if (!res.ret)
                break;

            if (res.ret != EAGAIN) {
                errno = res.ret;
                ret = -1;
                break;
            }
            if (!count && !detail)
                printf("%-16s %-5s %-6s %-10s %-10s %-28s %s\n", "NAME",
                       "PATHS", "MTU", "TX-LIMIT", "RX-LIMIT", "ALLOWED",
                       "DROPPED tx/rx/mtu/spoof");
            if (count && detail)
                printf("\n");
            if (detail)
                vx_peer_print_detail(res.tun_name, &res.peer_spec.info);
            else
                vx_peer_print_row(&res.peer_spec.info);
            count++;
        }
        if (!ret && !count) {
            if (detail) {
                vx_log("no such client\n");
                ret = -1;
                errno = 0;
            } else {
                printf("no clients\n");
            }
        }
    }
    if (ret == -1 && errno)
        perror("peer");

    ctl_delete(fd);
    return ret;
}
