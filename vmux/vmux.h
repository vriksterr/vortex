#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* There is no limit on the number of paths a tunnel can have (to a single peer;
 * vmux is point-to-point, not a mesh): paths and groups are kept in chunks that
 * grow as needed, a packet's path is found by a hash lookup, and the sending
 * path is chosen by a binary search over running totals (see vmux_get_path()
 * and vmux_select_path()). Memory is the only limit, apart from `maxpaths`,
 * which a server can set per client.
 *
 * VMUX_PATH_MAX (512) is no longer a limit of the engine. It is how many paths
 * one listing (`vortex path`) carries, through VMUX_PATH_LIST_MAX below; the
 * listing says how many there are in all when it is cut short. */
#define VMUX_PATH_MAX    (512U)
/* Local UDP sockets one vmux instance may open, shared across every path --
 * not one-per-remote. Lets a single logical path be split into this many
 * independent sub-flows (distinct source ports) for bandwidth aggregation
 * on long/high-RTT links, similar to parallel TCP streams, and backs the
 * SO_REUSEPORT receive-scaling pool vmux_create() opens (see its own
 * comment). The pool's backing array is allocated once, fixed at this
 * size, in vmux_create() -- not grown on demand -- specifically so worker
 * threads can read vmux->sock[] without synchronization (see
 * vmux_worker_loop()).
 *
 * Raised 256 -> 4096 (16x) alongside widening struct vmux_path_conf.sock
 * from unsigned char to uint16_t -- 256 was that field's own range, not a
 * deliberate design ceiling, and it was already tight enough that
 * combining several physical links with generous connections=N sub-flow
 * counts plus the SO_REUSEPORT reservation could plausibly approach it.
 * uint16_t comfortably covers this value with headroom to raise it
 * further later without another type change (max 65535). Not raised
 * further than this for now because vmux_worker_loop() stack-allocates a
 * struct pollfd plus an index per socket (~12 bytes each): at 4096 that's
 * ~48KB against the explicit 1MB worker stack (see bind.c's
 * pthread_attr_setstacksize()), comfortably within the ~768KB left after
 * that stack's existing ~256KB of packet buffers, but the tradeoff would
 * need re-examining before going much higher. Requests above this are
 * rejected, not clamped, since silently wrapping the index would corrupt
 * path identity. */
#define VMUX_SOCK_MAX    (4096U)
#define VMUX_PUBKEY_SIZE (32U)

/* Ring size backing a monitor path's own received-sequence-number window
 * (see struct vmux_path's `probe` member and "Probe-based path health" in
 * vmux.c). Fixed, always allocated as part of struct vmux_path -- same no-
 * realloc rationale as everything else sized this way in this header --
 * costing one byte per slot regardless of whether this path is ever used
 * as a monitor (most aren't). 600 covers a 10-minute probewindow/
 * proberecover at the default 1-second probe interval, generous headroom
 * over any sane configuration; a user-configured window/recover duration
 * longer than this, at whatever interval they chose, is clamped to it. */
#define VMUX_PROBE_RING_SIZE (600U)

/* How far a peer-reported probe seq is allowed to regress before
 * vmux_probe_recv() treats it as the peer's counter having restarted from
 * zero, rather than as an ordinarily-reordered late arrival -- see that
 * function's peer-report ordering guard. At the probe cadence this
 * piggybacks on (at most 1/s), a handful of slots is already generous
 * tolerance for real reordering; deliberately far smaller than
 * VMUX_PROBE_RING_SIZE, whose 10-minute sizing is tuned for the loss ring's
 * own purpose and would otherwise let an early restart hide as reordering
 * for minutes. */
#define VMUX_PEER_REPORT_REORDER_MAX (8U)

/* Hard wire-size ceiling: 65535 is UDP's own length-field maximum
 * (header + payload). Note that over IPv4 the practical limit is lower
 * (65507 = 65535 - 20-byte IPv4 header - 8-byte UDP header) -- a
 * configured value between 65508 and 65535 will pass every check here but
 * still fail at sendto() on an IPv4 path, since the datagram can't
 * physically fit in an IPv4 packet at that size. Fixed packet buffers
 * throughout vmux.c and bind.c are sized to this, so anything up to it is
 * memory-safe end-to-end regardless; the configured MTU
 * (struct vmux_path_conf.mtu) is clamped to this at the point it's applied
 * (vmux_mtu_apply()). The CLI is the layer that actually rejects an
 * out-of-range request with a clear error; this is only a last-resort
 * backstop, not a competing decision. */
#define VMUX_MTU_HARD_MAX (65535U)

/* How many packets a worker takes from the tunnel device and sends in one go
 * (vmux_conf.tx_batch). The buffers for the largest batch are allocated per
 * worker, so this is also the hard limit the CLI enforces. */
#define VMUX_TX_BATCH_MAX     (128U)
#define VMUX_TX_BATCH_DEFAULT (16U)

struct vmux;

enum vmux_state {
    VMUX_EMPTY = 0,
    VMUX_DOWN,
    VMUX_PASSIVE,
    VMUX_UP,
    VMUX_LAST,
};

enum vmux_path_status {
    VMUX_DELETING = 0,
    VMUX_PROBING,
    VMUX_DEGRADED,
    VMUX_LOSSY,
    VMUX_WAITING,
    VMUX_READY,
    VMUX_RUNNING,
    VMUX_LATE,
};

struct vmux_stat {
    uint64_t val;
    uint64_t var;
    int setup;
};

struct vmux_conf {
    uint64_t keepalive;
    uint64_t timetolerance;
    uint64_t kxtimeout;
    /* 0 (default) = disabled: a decrypted data packet is handed to
     * vmux_worker_loop()'s tun_write callback the instant it's decrypted,
     * exactly as before this existed. When set, vmux_worker_loop() briefly
     * buffers decrypted data packets (bounded by this duration, in the
     * same time unit as the other fields above) tunnel-wide -- across
     * every path, not per-path -- so packets that arrive out of order
     * because they crossed different physical paths get sorted back into
     * send order before delivery, instead of reaching whatever protocol
     * (typically TCP) rides the tunnel looking exactly like loss. Trades
     * added latency, bounded by this value, for a single flow being able
     * to use more of a multipath tunnel's combined throughput. See
     * "Packet resequencing" in docs/architecture.md. Only vmux_worker_loop()
     * honors this -- the single-packet vmux_recv()/vmux_send() API is
     * unaffected, by design (see vmux_worker_loop's own doc comment).
     *
     * Sequence-numbered resequencing: setting this also tells the peer
     * (in every control message) that we want sequence numbers. A peer that
     * understands the request then appends a 4-byte number to the data
     * packets it sends us -- inside the encrypted payload, from a start
     * time it announces in its own clock, so both ends always agree which
     * packets carry one -- and we release those strictly in number order,
     * waiting only for a number that is actually missing (at most this
     * window, and normally just the arrival path's reorder_hold plus a few
     * ms, then it is given up as lost). An in-order packet is never delayed,
     * so a lone packet on the fast path keeps the fast path's latency, and
     * back-to-back bursts come out in order, which the RTT-derived hold
     * alone cannot guarantee. Nothing is stamped toward a peer that has not
     * asked (reorderwindow off, or an older build), and packets from such a
     * peer are still resequenced by the RTT-derived hold as before. Each
     * direction is independent, like the option itself. Stamped packets are
     * 4 bytes longer than the path's nominal MTU allows for.
     *
     * strict_order (below) decides whether this sequence-number scheme is
     * used at all. With it on (the default) and a reorder_window set, we ask
     * the peer to stamp EVERY data packet, TCP included, and release them in
     * number order; TCP is only stamped if the peer says (a flag in the same
     * control message) that it understands it, so an older peer keeps
     * getting the old behaviour (UDP and the like stamped, TCP not). With it
     * off, nothing is stamped and only the RTT-derived hold below applies,
     * exactly as before this option existed. reorder_window alone is then
     * just how long a missing number may be waited for. */
    uint64_t reorder_window;
    /* Strict (sequence-number) ordering for TCP and everything else, see
     * above. A request value of 0 means "not given", 1 = off, 2 = on, so
     * `strictorder off` can be told apart from not passing the option (same
     * reason reorder_window carries a marker bit); what vmux_set() stores and
     * hands back is a plain 0 (off) or 1 (on). Defaults to on. */
    uint64_t strict_order;
    /* Most packets a worker reads from the tunnel device before it sends
     * them (encrypting each one, picking a path for each, then one sendmmsg
     * per socket). A smaller batch means shorter bursts on the wire, which
     * helps where a link has a shallow buffer, at the cost of more system
     * calls; a larger one is cheaper on CPU but burstier. 0 in a request
     * means "not given"; valid values are 1..VMUX_TX_BATCH_MAX (anything
     * larger is rejected by vmux_set()). Defaults to
     * VMUX_TX_BATCH_DEFAULT. Only affects what this end sends; it is not
     * sent to the peer. In a multi-client hub it is one value for the whole
     * hub (set without `peer`). Takes effect immediately. */
    uint64_t tx_batch;
};

union vmux_sockaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

struct vmux_path_conf {
    enum vmux_state state;
    union vmux_sockaddr local;
    union vmux_sockaddr remote;
    unsigned int local_ifindex;
    uint64_t tx_max_rate;
    uint64_t rx_max_rate;
    uint64_t beat;
    unsigned char pref;
    unsigned char fixed_rate;
    unsigned char loss_limit;
    unsigned char tx_pinned;
    uint16_t sock; /* index into the owning vmux's socket pool
                     * (0..vmux_get_sock_count()-1) this path sends and
                     * receives on -- local metadata, never sent to the
                     * peer, meaningful for both active and passive
                     * paths (unlike local_ifindex, never zeroed).
                     * Widened from unsigned char alongside VMUX_SOCK_MAX
                     * (see its own comment) -- was that field's own
                     * 0-255 range, not a deliberate ceiling. */
    uint64_t rtt_limit; /* synced from whichever side has `monitor` configured,
                          * same as probe_interval/probe_window/probe_recover
                          * below -- see their own comment. */
    uint64_t mtu; /* 0 = library default (VMUX_MTU_DEFAULT); clamped to
                   * VMUX_MTU_HARD_MAX regardless of what's requested -- see
                   * vmux_mtu_apply() */
    /* Probe-based path health (see "Probe-based path health" in vmux.c).
     * `monitor` marks this path as a dedicated health-check sub-flow:
     * vmux_select_path() never picks it for data, and it sends its probe on
     * a fixed cadence (probe_interval) regardless of the idle-driven beat
     * backoff every other path is subject to. The three tunables below --
     * plus rtt_limit above -- are only meaningful when monitor is set, and
     * only need setting on the active side's `path up`: vmux_send_msg()/
     * vmux_recv_msg() propagate all four to a passively-discovered peer path
     * the same way monitor/loss_limit themselves already do (see
     * vmux_recv_msg()'s tx_time==0 branch and struct vmux_msg's own comment
     * in vmux.c), so a VPS-side path that never runs its own `path up` still
     * ends up using the exact same window/recover/RTT budget the active
     * side configured, instead of silently falling back to its own
     * compiled-in defaults for whichever of these the active side didn't
     * happen to match. 0 means "use the compiled-in default" (see
     * VMUX_PROBE_*_DEFAULT in vmux.c) on whichever side has no explicit
     * `path up` of its own to set it from. */
    unsigned char monitor;
    uint64_t probe_interval;
    uint64_t probe_window;
    uint64_t probe_recover;
};

struct vmux_path {
    struct vmux_path_conf conf;
    enum vmux_path_status status;
    union vmux_sockaddr remote;
    struct vmux_stat rtt;
    struct {
        uint64_t total;
        uint64_t bytes;
        uint64_t time;
        uint64_t rate;
    } tx, rx;
    struct {
        struct {
            uint64_t total;
            uint64_t bytes;
            uint64_t time;
        } tx, rx;
        uint64_t time;
        uint64_t sent;
        uint64_t set;
    } msg;
    size_t mtu; /* the fixed wire size this path sends at -- always set (see
                 * vmux_mtu_apply()), no discovery/negotiation involved */
    /* Pooled across every path sharing this one's physical link (same
     * definition of "group" as select_weight above: same interface/local
     * address and remote address) -- recomputed once per vmux_update() tick,
     * identical value mirrored onto every member, from struct vmux_group's
     * own probe_has_monitor/probe_loss_pub/probe_degraded -- see "Probe-
     * based path health" in vmux.c. Byte-counter tx-loss/rx-loss used to be
     * pooled the same way here too (tx.loss/rx.loss above and their live
     * counterparts, plus group_tx_loss/group_rx_loss/group_tx_loss_live/
     * group_rx_loss_live) -- removed entirely along with the rest of that
     * mechanism, since `monitor` is mandatory on every path now.
     * group_probe_has_monitor lets display code (vortex path) tell "this
     * group has no monitor configured, ignore the other four" apart from
     * "it has one and it currently reads 0%". group_probe_loss/
     * group_probe_degraded are this side's own reading of what it receives
     * from the peer -- display/diagnostic only as of the peer-reporting
     * addition below; group_peer_probe_loss/group_peer_probe_degraded are
     * what the peer last reported about receiving from *us*, and
     * group_peer_probe_degraded is now the actual latched decision
     * vmux_path_update() uses for VMUX_LOSSY -- "should I keep sending this
     * way" has to depend on whether the peer is hearing us, not on whether
     * we're hearing the peer, which group_probe_degraded alone could never
     * tell it. See struct vmux_group's own comment in vmux.c for the full
     * rationale. */
    int group_probe_has_monitor;
    uint64_t group_probe_loss;
    int group_probe_degraded;
    uint64_t group_peer_probe_loss;
    int group_peer_probe_degraded;
    uint64_t group_rtt; /* average rtt.val across every currently-RUNNING
                          * member of the group -- same rationale as the loss
                          * figures above, applied to latency: one path's own
                          * RTT reading is only as fresh as its own last
                          * successful exchange, while the group figure
                          * reflects whichever member(s) most recently heard
                          * back. */
    uint64_t select_weight; /* recomputed once per vmux_update() tick, used by
                              * vmux_select_path() instead of tx.rate directly:
                              * equal to the average tx.rate across every
                              * RUNNING path sharing this one's physical
                              * identity (same interface/local address and
                              * remote address, regardless of which sub-flow
                              * socket each one uses). Sub-flows of the same
                              * physical link are therefore selected evenly
                              * regardless of which one currently measures
                              * fastest, while distinct physical links still
                              * split traffic proportional to their real
                              * measured capacity. tx.rate itself is left
                              * alone -- still each sub-flow's own genuine
                              * measured throughput, for display/diagnostics
                              * and for its own AIMD growth/decay. */
    uint64_t idle;
    uint64_t created; /* vmux_now() at creation, set once by vmux_get_path()
                        * and never touched again -- unlike `idle` (reused
                        * for traffic-gap tracking once a path goes
                        * RUNNING). vmux_now() is wall-clock-based (base_time
                        * + CLOCK_MONOTONIC, see its own comment) and so
                        * keeps advancing across a process restart on the
                        * same machine, not reset to 0 -- which is what lets
                        * this double as a freshness baseline: see
                        * `confirmed_live` just below and vmux_recv_msg()'s
                        * own comment for how the two combine. */
    int confirmed_live; /* set (never cleared) by vmux_recv_msg() the first
                          * time this path receives a genuine reply -- one
                          * whose echoed timestamp is >= `created` above,
                          * meaning it can only be answering something this
                          * process sent after this path existed, not a
                          * queued packet a since-dead peer is still
                          * flushing out. vmux_path_promote() (see its own
                          * comment) requires this before spending an fd on
                          * a passively-discovered path, closing a real gap
                          * a plain elapsed-time check left open: several
                          * stale packets can keep trickling out of a dead
                          * process's send queue for well over a second,
                          * long enough to fool a timer but never able to
                          * forge a reply to something that hadn't been
                          * sent yet when they were queued. */
    int traffic_idle; /* no real traffic in the last second. Refreshed every
                        * vmux_update() tick, so it stays current even if the
                        * peer goes fully silent -- see vmux_path_track()'s
                        * own use of it (single-socket keepalive backoff). */
    /* Only populated/meaningful when conf.monitor is set -- see "Probe-
     * based path health" in vmux.c. Sequence-gap based, not byte-counter
     * based: each side tracks gaps in what it *receives* from the peer,
     * entirely locally, no echo/round-trip involved, applied to both
     * directions here since both ends run this identical logic on their
     * own incoming stream. */
    struct {
        uint32_t tx_next;   /* next sequence number this side sends */
        uint64_t tx_last;   /* vmux_now() the last probe was sent, 0 = never */
        uint32_t rx_next;   /* next sequence number expected from the peer */
        uint64_t rx_last;   /* vmux_now() a probe from the peer was last
                              * successfully processed, 0 = never. Distinct
                              * from the ring below: the ring only advances
                              * on a genuine event, so a path that goes
                              * fully silent (not just lossy) would
                              * otherwise leave stale "mostly good" data
                              * sitting in the ring forever -- mirrors why
                              * vmux_path_track()'s own per-path idle-aging
                              * exists for the byte-counter trackers.
                              * vmux_path_track() reads this each tick to
                              * force a resync once a whole probe_window's
                              * worth of real time has passed with nothing
                              * received at all. */
        int rx_sync;        /* 0 until the first probe has ever been seen,
                              * so a fresh/restarted peer's own numbering is
                              * adopted instead of read as one huge gap */
        unsigned char seen[VMUX_PROBE_RING_SIZE]; /* ring: 1 = that sequence
                              * number's slot was received, 0 = missed;
                              * indexed by seq % VMUX_PROBE_RING_SIZE */
        uint32_t peer_report_seq; /* seq of the last probe whose piggybacked
                              * peer-report bytes were actually applied to
                              * the group (see vmux_group_peer_report()) --
                              * a later-arriving but lower-numbered probe
                              * (reordered in flight) must not be allowed to
                              * overwrite a report from a probe we already
                              * applied, so a report is only ever adopted
                              * when its own seq is newer than this. */
        int peer_report_sync; /* 0 until the first report has ever been
                              * applied, so that first one is never rejected
                              * for "not being newer than" an unset zero */
    } probe;
    uint64_t reorder_hold; /* recomputed once per vmux_update() tick, same
                             * cadence as select_weight above: how much
                             * longer, relative to the tunnel's current
                             * slowest RUNNING path, a packet arriving on
                             * this specific path might still need to wait
                             * for an earlier-sent packet on that slower
                             * path to arrive. Zero for the slowest path
                             * itself (or when reorder_window is off), and
                             * zero for any path within ~0.5ms of it --
                             * below that is RTT measurement noise, not a
                             * real path difference.
                             * Used by vmux_reorder_insert() (see vmux.c) so
                             * held duration adapts to each path's real
                             * measured RTT instead of one flat delay
                             * applied to every packet regardless of which
                             * path it took. */
};

struct vmux_error {
    union vmux_sockaddr addr;
    uint64_t time;
    uint64_t count;
};

struct vmux_errors {
    struct vmux_error decrypt;
    struct vmux_error clocksync;
    struct vmux_error keyx;
};

/* A listing of a tunnel's paths holds at most VMUX_PATH_LIST_MAX of them;
 * `total` is how many there really are (there is no limit on the number of
 * paths a tunnel can have, only on how many one listing carries). */
#define VMUX_PATH_LIST_MAX VMUX_PATH_MAX

struct vmux_paths {
    struct vmux_path path[VMUX_PATH_LIST_MAX];
    unsigned count;
    unsigned total;
};

/* TUN access callbacks -- see vmux_worker_loop(). */
typedef int (*vmux_tun_read_fn)(int fd, void *buf, size_t size);
typedef int (*vmux_tun_write_fn)(int fd, const void *buf, size_t size);

/* ------------------------------------------------------------------------
 * Multi-client ("hub") support.
 *
 * A struct vmux is exactly one session with exactly one peer. A hub owns the
 * shared UDP socket pool and holds one fully independent struct vmux per
 * client ("peer"): separate keys, key rotation, paths, health state, rate
 * window, MTU, tunables and reorder buffers, so nothing one client does or
 * is configured with can leak into another. Only the sockets, the worker
 * threads and the TUN device are shared.
 *
 * Per-peer server-side overrides live in struct vmux_policy: whatever the
 * server sets there always wins over what the client advertises in its
 * control messages. ------------------------------------------------------ */

#define VMUX_HUB_PEERS_MAX   (128U)
#define VMUX_HUB_NAME_MAX    (32U)
#define VMUX_HUB_ALLOWED_MAX (16U)

/* An inner (tunnelled) network a peer is allowed to own. */
struct vmux_prefix {
    unsigned char family; /* AF_INET or AF_INET6 */
    unsigned char len;    /* prefix length in bits */
    unsigned char addr[16];
};

#define VMUX_POLICY_TX_RATE   (1U << 0)
#define VMUX_POLICY_RX_RATE   (1U << 1)
#define VMUX_POLICY_MTU       (1U << 2)
#define VMUX_POLICY_PREF      (1U << 3)
#define VMUX_POLICY_LOSSLIMIT (1U << 4)
#define VMUX_POLICY_RTTLIMIT  (1U << 5)
#define VMUX_POLICY_MAXPATHS  (1U << 6)

/* Server-side settings enforced for one peer. Only fields whose bit is set in
 * `set` are enforced; everything else keeps following the client. */
struct vmux_policy {
    unsigned int set;
    uint64_t tx_max_rate;   /* bytes/s, cap on what we send to this peer */
    uint64_t rx_max_rate;   /* bytes/s, advertised as what it may send us */
    uint64_t mtu;           /* fixed wire size for this peer's paths */
    unsigned char pref;     /* stored as the internal (unshifted) value */
    unsigned char loss_limit; /* 0..255 */
    uint64_t rtt_limit;     /* microseconds */
    unsigned int max_paths; /* concurrent paths this peer may hold */
};

int vmux_set_policy (struct vmux *, const struct vmux_policy *);
int vmux_get_policy (struct vmux *, struct vmux_policy *);

struct vmux_hub;

struct vmux_hub_peer_info {
    char name[VMUX_HUB_NAME_MAX];
    int active;
    unsigned int allowed_count;
    struct vmux_prefix allowed[VMUX_HUB_ALLOWED_MAX];
    struct vmux_policy policy;
    struct vmux_conf conf;
    size_t mtu;
    unsigned int path_count;
    uint64_t tx_drop_rate;   /* packets dropped: this peer's rate window empty */
    uint64_t rx_drop_rate;   /* packets dropped: peer sent faster than its rx limit */
    uint64_t tx_drop_mtu;    /* packets too large for this peer's paths */
    uint64_t rx_drop_spoof;  /* inner source address not owned by this peer */
};

struct vmux_hub_stats {
    uint64_t tx_drop_noroute; /* no peer owns the inner destination address */
    uint64_t rx_drop_unknown; /* datagrams from sources matching no peer */
    uint64_t rx_drop_limited; /* identification attempts refused by the limiter */
};

typedef void (*vmux_hub_oversize_fn)(int tun_fd, const void *pkt, size_t len,
                                    size_t mtu);

struct vmux_hub *vmux_hub_create (union vmux_sockaddr *, int *aes);
void            vmux_hub_delete (struct vmux_hub *);

int vmux_hub_peer_add (struct vmux_hub *, const char *name,
                      const unsigned char *key,
                      const struct vmux_prefix *allowed, unsigned int count,
                      const struct vmux_policy *);
int vmux_hub_peer_set (struct vmux_hub *, const char *name,
                      const struct vmux_prefix *allowed, int allowed_set,
                      unsigned int allowed_count,
                      const struct vmux_policy *set, unsigned int unset,
                      struct vmux_conf *conf);
int vmux_hub_peer_del (struct vmux_hub *, const char *name);
struct vmux *vmux_hub_peer_get (struct vmux_hub *, const char *name);
int vmux_hub_peer_info (struct vmux_hub *, unsigned int slot,
                       struct vmux_hub_peer_info *);
unsigned int vmux_hub_peer_count (struct vmux_hub *);
void vmux_hub_set_defaults (struct vmux_hub *, struct vmux_conf *);
void vmux_hub_get_stats (struct vmux_hub *, struct vmux_hub_stats *);

int          vmux_hub_update (struct vmux_hub *);
size_t       vmux_hub_get_mtu (struct vmux_hub *);
unsigned int vmux_hub_get_sock_count (struct vmux_hub *);
int          vmux_hub_get_fd (struct vmux_hub *, unsigned int sock);

int vmux_hub_worker_loop (struct vmux_hub *, unsigned int worker_index,
                         unsigned int worker_count,
                         const int *tun_fds, unsigned int tun_fd_count,
                         vmux_tun_read_fn tun_read, vmux_tun_write_fn tun_write,
                         vmux_hub_oversize_fn oversize,
                         const volatile sig_atomic_t *quit);

struct vmux *vmux_create (union vmux_sockaddr *, unsigned char *, int *);
void        vmux_delete (struct vmux *);

int vmux_set      (struct vmux *, struct vmux_conf *);
int vmux_set_path (struct vmux *, struct vmux_path_conf *);
int vmux_rebind_path (struct vmux *, unsigned int, union vmux_sockaddr *,
                     unsigned int, union vmux_sockaddr *, unsigned int);

/* Grows the instance's local socket pool to `count` sockets (lazily, and
 * capped at VMUX_SOCK_MAX), all bound to an ephemeral port on the same
 * address family as the original vmux_create() socket. Monotonic -- never
 * shrinks. A struct vmux_path_conf.sock value must be < the pool size
 * (vmux_get_sock_count()) or vmux_set_path() rejects it with EINVAL, so grow
 * the pool before configuring paths that reference new indices. Returns 0
 * on success, -1 (errno set) on failure, leaving sock_count unchanged. Safe
 * to call while worker threads are running (see vmux_worker_loop()). */
int vmux_set_sock_count (struct vmux *, unsigned int count);

int vmux_update    (struct vmux *);
int vmux_send_wait (struct vmux *);

/* Single-packet API -- unchanged in meaning, now internally synchronized
 * against any concurrently running vmux_worker_loop() threads (see below),
 * so a caller may still use these directly (as vmux/test.c does) instead of
 * running worker threads at all. */
int vmux_recv (struct vmux *, unsigned int sock, void *, size_t);
int vmux_send (struct vmux *, const void *, size_t);

/* How many worker threads vmux_worker_loop() is meant to be run with on this
 * host: min(usable cores - 1, VMUX_WORKERS_MAX) by default ("usable" = the
 * cores this process is allowed to run on, so a CPU restriction is
 * respected), or whatever
 * vmux_set_worker_count() last set explicitly (see its own comment). Just a
 * sizing hint -- vmux_worker_loop() itself doesn't care how many copies of
 * it are actually running. */
unsigned int vmux_worker_count (void);

/* Overrides vmux_worker_count()'s automatic cores-1 sizing with an explicit
 * value -- every worker thread contends for the same shared TUN device
 * wakeup (see vmux_worker_loop()'s own comment), so the number of sub-flows
 * actually in use, not raw core count, is what determines the efficient
 * worker count; only the operator configuring `connections N` knows that
 * number in advance. Pass 0 to go back to the automatic sizing. Clamped
 * to [1, min(4 x usable cores, 64)] -- deliberately allowed to exceed the
 * core count, since more workers than cores lets sub-flows divide evenly
 * (16 paths over 3 workers is 6/5/5, over 8 is 2 each) while the scheduler
 * spreads the threads; call after any CPU restriction is in place, since
 * the ceiling is computed from the cores available at that moment. Must be called
 * before vmux_create(), which reads vmux_worker_count() once to size its
 * own SO_REUSEPORT receive-scaling pool (see its own comment). */
void vmux_set_worker_count (unsigned int n);

/* vmux.c is a standalone transport library and deliberately knows nothing
 * about vortex's own TUN device handling (platform-specific framing,
 * etc. -- see src/tun.h) -- vmux_worker_loop() takes it as a pair of plain
 * function pointers instead of linking against src/tun.c directly. Both
 * signatures match src/tun.h's tun_read()/tun_write() exactly, so a caller
 * in this repo can pass those two functions straight through with no
 * wrapping needed. */

/* Runs one worker's full packet-processing loop: waits (via poll()) on
 * every TUN queue fd in `tun_fds` and this worker's share of the instance's
 * socket pool, and for whichever is ready, does the complete job itself
 * with no hand-off to another thread -- receive, decrypt, look up the
 * path, update its stats, write to TUN (via `tun_write`, always through
 * `tun_fds[0]` -- any queue fd can inject a packet into the interface, so
 * which one is used for writing doesn't matter); or read TUN (via
 * `tun_read`, from whichever of `tun_fds` was actually readable), encrypt,
 * pick a path, send. Safe to run from multiple threads concurrently
 * against the same `struct vmux *` and the same `tun_fds` -- that is the
 * intended use: start vmux_worker_count() threads, each with its own
 * worker_index in [0, worker_count), all given the *same* `tun_fds`/
 * `tun_fd_count`, so the full pipeline -- not just encryption -- spreads
 * across cores instead of running on one thread while only crypto is
 * parallel.
 *
 * `worker_index`/`worker_count` partition the socket pool: this call only
 * polls sock indices i where (i % worker_count == worker_index), so a
 * given socket is polled by exactly one thread rather than every thread
 * waking on every socket's readiness (a thundering herd where only one
 * waker ever does useful work per event). The TUN queues in `tun_fds` are
 * deliberately NOT partitioned the same way, even when the caller opened
 * one queue per worker (multi-queue TUN, see src/bind.c) -- every worker
 * polls every queue. Handing each worker one *exclusive* queue instead
 * (tried first) ties that queue's traffic to whichever kernel flow-hash
 * bucket the OS's queue selection happens to land it in for the life of
 * that flow: confirmed live, a single dominant flow (or several hashing
 * into the same bucket) then pins nearly all the real work onto that one
 * queue's one worker forever, no matter how many other workers/queues
 * exist -- one thread measured at ~88% CPU while the other seven combined
 * stayed under 17%, on 8 workers/8 queues. Every worker polling every
 * queue means any idle worker can drain a busy queue's next ready batch,
 * so a kernel-side hot queue no longer pins its processing to one fixed
 * thread. This is a smaller herd than the pre-multi-queue shared-single-fd
 * design it might look like: that one had one fd shared by potentially far
 * more workers than real flows; this has `tun_fd_count` fds (normally one
 * per worker already) each shared by `worker_count` pollers, and the same
 * per-fd batching below keeps losing an occasional race cheap. Concurrent
 * tun_read() from multiple threads against the same queue fd is safe, the
 * same way it already is for a single shared fd -- the kernel hands each
 * call a distinct queued packet.
 *
 * Each ready fd is drained in batches (up to 16 packets per wakeup, via
 * recvmmsg()/sendmmsg() on Linux, or an equivalent bounded loop elsewhere)
 * rather than one packet per poll() iteration. Every caller must use the
 * same worker_count, tun_fds, and tun_fd_count for all threads of one
 * `struct vmux *` (mismatched values just waste polling coverage rather
 * than corrupting state, but there is no reason to do it).
 *
 * Concurrent recvmsg()/recvmmsg()/sendmsg()/sendmmsg()/tun_read()/
 * tun_write() from multiple threads against the same socket or TUN fd are
 * safe (the kernel hands each call a distinct packet); everything else the
 * pipeline touches (path state, session keys, the socket pool) is
 * internally locked, and those locks are never held across a syscall or
 * the actual AEAD operation, so the syscalls and the crypto math itself
 * still run fully concurrently across threads.
 *
 * Blocks until `*quit` is observed true (checked between iterations, so
 * a thread may still be inside one iteration -- typically a bounded
 * poll() wait -- when the flag flips) or a fatal error occurs, then
 * returns 0 (quit requested) or -1 (errno set). */
int vmux_worker_loop (struct vmux *vmux, unsigned int worker_index,
                     unsigned int worker_count,
                     const int *tun_fds, unsigned int tun_fd_count,
                     vmux_tun_read_fn tun_read, vmux_tun_write_fn tun_write,
                     const volatile sig_atomic_t *quit);

int    vmux_get_errors    (struct vmux *, struct vmux_errors *);
int    vmux_get_fd        (struct vmux *, unsigned int sock);
unsigned int vmux_get_sock_count (struct vmux *);
size_t vmux_get_mtu       (struct vmux *);
int    vmux_get_paths     (struct vmux *, struct vmux_paths *,
                          union vmux_sockaddr *, union vmux_sockaddr *);
