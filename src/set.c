#include "common.h"
#include "ctl.h"
#include "argz.h"

int
vx_set(int argc, char **argv, void *data)
{
    const char *dev = NULL;
    const char *peer = NULL;
    struct argz_ull kx = {.suffix = argz_time_suffix};
    struct argz_ull tt = {.suffix = argz_time_suffix};
    struct argz_ull ka = {.suffix = argz_time_suffix};
    struct argz_ull rw = {.suffix = argz_time_suffix};
    int strict = 0;

    struct argz z[] = {
        {"dev",           "Tunnel device",       vx_argz_dev, &dev},
        {"peer",          "Only this client of a multi-client tunnel",
                                                     argz_str,  &peer},
        {"kxtimeout",     "Key rotation timeout",   argz_ull,  &kx},
        {"timetolerance", "Clock sync tolerance",   argz_ull,  &tt},
        {"keepalive",     "Keep alive timeout",     argz_ull,  &ka},
        {"reorderwindow", "Longest wait for a missing packet (default off)",
                                                     argz_ull,  &rw},
        {"strictorder",   "Number packets (TCP too) and release them in "
                          "order: on|off (default on)",
                                                     vx_argz_onoff, &strict},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    struct ctl_msg req = {
        .type = CTL_CONF,
        .conf = {
            .kxtimeout      = kx.value * UINT64_C(1000),
            .timetolerance  = tt.value * UINT64_C(1000),
            .keepalive      = ka.value * UINT64_C(1000),
            /* Same 0-means-unchanged convention as every other conf field
             * here would normally make `reorderwindow 0` indistinguishable
             * from not passing the flag at all -- no way to ever turn it
             * back off once set, short of restarting the process. Steal the
             * low bit as an explicit "this flag was given" marker instead
             * (same trick path.c's own `pref` field already relies on):
             * the real value only ever needs even microsecond counts here
             * (already *1000 from a millisecond-granularity CLI value), so
             * the low bit is always free for it. vmux_set() shifts it back
             * out before ever storing or returning it. */
            .reorder_window = argz_is_set(z, "reorderwindow")
                             ? ((rw.value * UINT64_C(1000)) << 1) | 1
                             : 0,
            .strict_order = (uint64_t)strict,
        },
    }, res = {0};

    if (peer) {
        if (strlen(peer) >= sizeof(req.peer)) {
            vx_log("client name is too long\n");
            return -1;
        }
        memcpy(req.peer, peer, strlen(peer) + 1);
    }

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return -1;
    }
    int ret = ctl_reply(fd, &res, &req);

    if (!ret) {
        char t0[32], t1[32], t2[32], t3[32];
        vx_totime(t0, sizeof(t0), res.conf.kxtimeout      / 1000);
        vx_totime(t1, sizeof(t1), res.conf.timetolerance  / 1000);
        vx_totime(t2, sizeof(t2), res.conf.keepalive      / 1000);
        vx_totime(t3, sizeof(t3), res.conf.reorder_window / 1000);

        printf("set dev %s kxtimeout %s timetolerance %s keepalive %s "
               "reorderwindow %s strictorder %s\n",
                res.tun_name, t0, t1, t2, t3,
                res.conf.strict_order ? "on" : "off");
        if (strict == 2 && !res.conf.reorder_window)
            vx_log("note: strictorder is on but reorderwindow is 0, so "
                   "nothing is reordered; set reorderwindow (for example "
                   "100ms)\n");
    }
    if (ret == -1 && errno)
        perror("set");

    ctl_delete(fd);

    return ret;
}
