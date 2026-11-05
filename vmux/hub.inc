/* ==========================================================================
 * Multi-client hub -- included at the end of vmux.c (it reuses that file's
 * static internals, so it must live in the same translation unit).
 *
 * One hub = one shared UDP socket pool + N fully independent struct vmux
 * sessions, one per client ("peer"). See "Multi-client" in vmux.h for the
 * isolation guarantees; this file is the machinery behind them.
 *
 * Packet identification (RX): a datagram's source address is looked up in a
 * lock-free cache that maps it to a peer. A hit goes straight to that peer's
 * session. A miss is only ever resolved for *control* messages -- a client's
 * paths always announce themselves with one before carrying data. Every
 * control message ends with a short client identifier (a hash of the client's
 * key and a 5-minute time window), which is looked up in a table to find the
 * one client to check; the check itself is the decryption with that client's
 * key, so a wrong or forged identifier gets nowhere. This only runs for
 * sources not already known. Data from an unknown source is dropped. A client
 * roaming to a new address is recognised the same way.
 *
 * Routing (TX): the inner destination address of each packet read from the
 * TUN selects the peer by longest-prefix match over the peers' allowed
 * prefixes. On RX the inner source must belong to the peer the datagram was
 * authenticated as, so one client cannot spoof another's address.
 *
 * Concurrency: the peer table, route snapshots and source cache are read
 * lock-free by worker threads (atomics; peer slots and sessions are never
 * freed while the hub runs). Only add/set/del -- always called from the one
 * housekeeping thread -- take admin_lock.
 * ========================================================================== */

/* There is no fixed limit on the number of clients: peer slots live in chunks
 * that are allocated as the client count grows (a slot never moves, so workers
 * can keep reading them without a lock). The only ceiling is the chunk-pointer
 * array below, about a billion clients, far past what memory would allow. */
#define VMUX_HUB_CHUNK_BITS    (10U)
#define VMUX_HUB_CHUNK         (1U << VMUX_HUB_CHUNK_BITS)
#define VMUX_HUB_CHUNKS_MAX    (1U << 20)

/* Source-address cache: starts small and grows with the client count (see
 * vmux_hub_cache_grow()). Power of two. */
#define VMUX_HUB_SRC_CACHE_MIN (4096U)
#define VMUX_HUB_SRC_CACHE_MAX (1U << 26)
/* Each identification costs one table lookup and one decryption now, not a
 * decryption per client, so the flood limit can be much higher. */
#define VMUX_HUB_IDENT_PER_SEC (20000U)
/* Anything replaced or removed while workers may still be reading it (tables,
 * route snapshots, a removed client's session) is parked this long before it
 * is freed. */
#ifndef VMUX_HUB_RETIRE_KEEP
#define VMUX_HUB_RETIRE_KEEP   (60 * VMUX_ONE_SEC)
#endif

/* Open-addressing table of client identifiers. e[2*i] is the identifier (0 =
 * empty slot), e[2*i+1] the owning peer's slot index + 1. It holds, for every
 * active client, the identifiers of the time windows around `window`, so a
 * client whose clock is somewhat off is still found. Immutable once
 * published. */
struct vmux_hub_idtab {
    unsigned int mask; /* number of entries - 1, a power of two minus one */
    unsigned int used; /* entries ever filled in (dead ones included); admin only */
    unsigned int span; /* windows on each side of `window` that are included */
    uint64_t window;   /* the window the table is centred on */
    uint64_t e[];
};
#define VMUX_HUB_QLEN          (128U)   /* packets a client may have waiting */
#define VMUX_HUB_QSLOT         (2048U)  /* larger packets are never queued */
#define VMUX_HUB_QMIN_BYTES    (32768U)

struct vmux_hub_q;

#if !defined EKEYREJECTED
#define EKEYREJECTED EINVAL
#endif

struct vmux_hub_routes {
    unsigned int count;
    struct vmux_prefix prefix[VMUX_HUB_ALLOWED_MAX];
};

struct vmux_hub;

struct vmux_hub_peer {
    unsigned int index;            /* this slot's number, fixed */
    struct vmux_hub *hub;
    int dirty_reorder;             /* atomic: packets may be waiting in its reorder buffers */
    int dirty_q;                   /* atomic: packets may be waiting in its shaping queue */
    char name[VMUX_HUB_NAME_MAX];
    int used;
    int active;                    /* atomic */
    struct vmux *vmux;               /* atomic */
    struct vmux_hub_routes *routes; /* atomic; immutable snapshot */
    size_t tx_mtu;                 /* atomic; largest inner packet we may send */
    uint64_t tx_drop_rate;         /* atomic counters */
    uint64_t tx_drop_mtu;
    uint64_t rx_drop_spoof;
    uint64_t rx_drop_rate;
    pthread_mutex_t rx_lock;       /* guards the ingress token bucket */
    uint64_t rx_tokens;
    uint64_t rx_time;
    pthread_mutex_t q_lock;        /* guards q */
    struct vmux_hub_q *q;           /* shaping queue, allocated on first use */
    unsigned int q_count;          /* atomic mirror of q->count */
};

/* Source address -> client cache. A word is the high 32 bits of the source
 * hash (a tag) and the client's slot number + 1 in the low 32 bits. */
struct vmux_hub_cache {
    unsigned int mask;
    uint64_t e[];
};

enum { VMUX_RETIRE_FREE, VMUX_RETIRE_SESSION };

struct vmux_hub_retired {
    void *ptr;
    int kind;
    uint64_t time;
    struct vmux_hub_peer *slot; /* for a session: the slot that pointed at it */
};

struct vmux_hub_rtab;

struct vmux_hub {
    int sock[VMUX_SOCK_MAX];
    unsigned int sock_count;
    int sock_v4, sock_v6;
    sa_family_t sock_family;
    int aes;
    struct vmux_conf defaults;
    pthread_mutex_t admin_lock;
    struct vmux_hub_peer **chunk;   /* VMUX_HUB_CHUNKS_MAX pointers, filled on demand */
    unsigned int *chunk_dirty;      /* [kind][chunk]: how many slots of the chunk are flagged */
    unsigned int peer_hwm; /* atomic: slots ever used */
    struct vmux_hub_cache *srccache; /* atomic */
    struct vmux_hub_retired *retired; /* guarded by admin_lock */
    unsigned int retired_count, retired_cap;
    unsigned int *free_slots;       /* reusable slot numbers, guarded by admin_lock */
    unsigned int free_count, free_cap;
    uint64_t tx_drop_noroute; /* atomic counters */
    uint64_t rx_drop_unknown;
    uint64_t rx_drop_limited;
    uint64_t ident_sec;
    uint64_t ident_count;
    /* Client identifier table (see vmux_hub_idtab_rebuild()). idtab is read
     * without a lock by every worker; a replaced table is kept for a while
     * (idtab_old) before it is freed, in case a worker is still looking
     * something up in it. */
    struct vmux_hub_idtab *idtab;
    struct vmux_hub_rtab *rtab;     /* route index, see vmux_hub_route() */
    unsigned int rt_cnt[2][129];     /* prefixes per length (v4, v6); admin only */
    uint64_t rt_bits[2][3];          /* lengths that have any; atomic */
};

static void vmux_hub_idtab_rebuild(struct vmux_hub *hub);
static void vmux_hub_rt_add(struct vmux_hub *hub, const struct vmux_hub_peer *p);
static void vmux_hub_rt_del(struct vmux_hub *hub, const struct vmux_hub_peer *p,
                           const struct vmux_hub_routes *r);
static void vmux_hub_id_add(struct vmux_hub *hub, const struct vmux_hub_peer *p);
static void vmux_hub_id_del(struct vmux_hub *hub, const struct vmux_hub_peer *p);

#define VMUX_AINC(P) ((void)__atomic_fetch_add((P), 1, __ATOMIC_RELAXED))

/* The slot with this number, or NULL if it does not exist (yet). */
static inline struct vmux_hub_peer *
vmux_hub_peer_at(const struct vmux_hub *hub, unsigned int i)
{
    const unsigned int c = i >> VMUX_HUB_CHUNK_BITS;

    if (c >= VMUX_HUB_CHUNKS_MAX)
        return NULL;

    struct vmux_hub_peer *chunk = __atomic_load_n(&hub->chunk[c], __ATOMIC_ACQUIRE);

    return chunk ? &chunk[i & (VMUX_HUB_CHUNK - 1U)] : NULL;
}

/* Which clients have work waiting. Walking every client on each pass of every
 * worker would cost more and more as clients are added, so a client flags itself
 * when it buffers a packet (reorder buffers, kind VMUX_HUB_DIRTY_REORDER) or
 * queues one for its rate limit (VMUX_HUB_DIRTY_Q), and the workers only visit
 * flagged clients. A per-chunk count lets whole chunks with nothing flagged be
 * skipped. Whoever clears a flag must look again afterwards and set it if work
 * is still pending; whoever adds work sets it after adding. */
#define VMUX_HUB_DIRTY_REORDER 0
#define VMUX_HUB_DIRTY_Q       1

static inline int *
vmux_hub_dirty_flag(struct vmux_hub_peer *p, int kind)
{
    return kind == VMUX_HUB_DIRTY_Q ? &p->dirty_q : &p->dirty_reorder;
}

static void
vmux_hub_mark(struct vmux_hub *hub, struct vmux_hub_peer *p, int kind)
{
    if (__atomic_exchange_n(vmux_hub_dirty_flag(p, kind), 1, __ATOMIC_ACQ_REL) == 0)
        __atomic_fetch_add(&hub->chunk_dirty[(size_t)kind * VMUX_HUB_CHUNKS_MAX +
                                             (p->index >> VMUX_HUB_CHUNK_BITS)],
                           1U, __ATOMIC_RELAXED);
}

static int
vmux_hub_unmark(struct vmux_hub *hub, struct vmux_hub_peer *p, int kind)
{
    if (__atomic_exchange_n(vmux_hub_dirty_flag(p, kind), 0, __ATOMIC_ACQ_REL) == 0)
        return 0;

    __atomic_fetch_sub(&hub->chunk_dirty[(size_t)kind * VMUX_HUB_CHUNKS_MAX +
                                         (p->index >> VMUX_HUB_CHUNK_BITS)],
                       1U, __ATOMIC_RELAXED);
    return 1;
}

/* The next flagged client at or after *cursor, or NULL. */
static struct vmux_hub_peer *
vmux_hub_dirty_next(struct vmux_hub *hub, int kind, unsigned int *cursor)
{
    const unsigned int hwm = __atomic_load_n(&hub->peer_hwm, __ATOMIC_ACQUIRE);
    unsigned int i = *cursor;

    while (i < hwm) {
        if (!(i & (VMUX_HUB_CHUNK - 1U)) &&
            !__atomic_load_n(&hub->chunk_dirty[(size_t)kind * VMUX_HUB_CHUNKS_MAX +
                                               (i >> VMUX_HUB_CHUNK_BITS)],
                             __ATOMIC_RELAXED)) {
            i += VMUX_HUB_CHUNK;
            continue;
        }
        struct vmux_hub_peer *p = vmux_hub_peer_at(hub, i++);

        if (p && __atomic_load_n(vmux_hub_dirty_flag(p, kind), __ATOMIC_ACQUIRE)) {
            *cursor = i;
            return p;
        }
    }
    *cursor = i;
    return NULL;
}

/* Whether a client still has anything in its reorder buffers. */
static int
vmux_hub_reorder_pending(struct vmux *vmux)
{
    struct vmux_reorder *ro = &vmux->reorder;

    pthread_mutex_lock(&ro->lock);

    const int pending = ro->count || ro->seq_count;

    pthread_mutex_unlock(&ro->lock);
    return pending;
}

/* A steady clock for retirement ages: the wall clock may jump. */
static uint64_t
vmux_hub_mono(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * VMUX_ONE_SEC + (uint64_t)ts.tv_nsec / 1000U;
}

/* Parks something that workers may still be reading (a replaced table or route
 * snapshot, a removed client's session) until it is safe to free it. For a
 * session, `slot` is the slot that points at it. Caller holds admin_lock. If
 * memory for the list runs out the item is simply never freed. */
static void
vmux_hub_retire(struct vmux_hub *hub, void *ptr, int kind,
               struct vmux_hub_peer *slot)
{
    if (!ptr)
        return;

    if (hub->retired_count == hub->retired_cap) {
        const unsigned int cap = hub->retired_cap ? hub->retired_cap * 2U : 64U;
        struct vmux_hub_retired *n = realloc(hub->retired, cap * sizeof(*n));

        if (!n)
            return;
        hub->retired = n;
        hub->retired_cap = cap;
    }
    struct vmux_hub_retired *e = &hub->retired[hub->retired_count++];

    e->ptr = ptr;
    e->kind = kind;
    e->slot = slot;
    e->time = vmux_hub_mono();
}

/* Remembers a slot that can take a new client. Caller holds admin_lock. */
static void
vmux_hub_free_slot_push(struct vmux_hub *hub, unsigned int index)
{
    if (hub->free_count == hub->free_cap) {
        const unsigned int cap = hub->free_cap ? hub->free_cap * 2U : 64U;
        unsigned int *n = realloc(hub->free_slots, cap * sizeof(*n));

        if (!n)
            return;
        hub->free_slots = n;
        hub->free_cap = cap;
    }
    hub->free_slots[hub->free_count++] = index;
}

/* Frees whatever has been parked long enough. A removed client's slot is made
 * reusable here, once its session is really gone. Caller holds admin_lock. */
static void
vmux_hub_reap(struct vmux_hub *hub)
{
    const uint64_t now = vmux_hub_mono();
    unsigned int keep = 0;

    for (unsigned int i = 0; i < hub->retired_count; i++) {
        struct vmux_hub_retired *e = &hub->retired[i];

        if (now - e->time <= VMUX_HUB_RETIRE_KEEP) {
            hub->retired[keep++] = *e;
            continue;
        }
        if (e->kind == VMUX_RETIRE_SESSION) {
            struct vmux_hub_peer *s = e->slot;

            if (s && __atomic_load_n(&s->vmux, __ATOMIC_ACQUIRE) == e->ptr) {
                __atomic_store_n(&s->vmux, NULL, __ATOMIC_RELEASE);
                if (!VMUX_ALOAD(&s->active)) {
                    /* nobody is using the slot any more: make it anonymous
                     * so the name can be used again, and hand it out again */
                    free(s->routes);
                    s->routes = NULL;
                    s->used = 0;
                    s->name[0] = 0;
                    vmux_hub_free_slot_push(hub, s->index);
                }
            }
            vmux_delete(e->ptr);
        } else {
            free(e->ptr);
        }
    }
    hub->retired_count = keep;
}

/* Makes the source cache bigger once there are many clients, so that a client's
 * sources are not constantly pushed out. Entries are not copied: the next
 * control message of each client puts it back. Caller holds admin_lock. */
static void
vmux_hub_cache_grow(struct vmux_hub *hub)
{
    struct vmux_hub_cache *old = __atomic_load_n(&hub->srccache, __ATOMIC_ACQUIRE);
    size_t want = (size_t)old->mask + 1U;
    const size_t need = (size_t)hub->peer_hwm * 64U;

    while (want < need && want < VMUX_HUB_SRC_CACHE_MAX)
        want <<= 1;

    if (want == (size_t)old->mask + 1U)
        return;

    struct vmux_hub_cache *c = calloc(1, sizeof(*c) + want * sizeof(uint64_t));

    if (!c)
        return;

    c->mask = (unsigned int)(want - 1U);
    __atomic_store_n(&hub->srccache, c, __ATOMIC_RELEASE);
    vmux_hub_retire(hub, old, VMUX_RETIRE_FREE, NULL);
}

static uint64_t
vmux_hub_mix(uint64_t h, const void *data, size_t n)
{
    const unsigned char *p = data;

    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static uint64_t
vmux_hub_src_hash(const union vmux_sockaddr *a)
{
    uint64_t h = UINT64_C(14695981039346656037);
    const unsigned char fam = (unsigned char)a->sa.sa_family;

    h = vmux_hub_mix(h, &fam, 1);
    if (a->sa.sa_family == AF_INET) {
        h = vmux_hub_mix(h, &a->sin.sin_port, sizeof(a->sin.sin_port));
        h = vmux_hub_mix(h, &a->sin.sin_addr, sizeof(a->sin.sin_addr));
    } else if (a->sa.sa_family == AF_INET6) {
        h = vmux_hub_mix(h, &a->sin6.sin6_port, sizeof(a->sin6.sin6_port));
        h = vmux_hub_mix(h, &a->sin6.sin6_addr, sizeof(a->sin6.sin6_addr));
    }
    h ^= h >> 29;
    h *= UINT64_C(0xBF58476D1CE4E5B9);
    h ^= h >> 32;
    return h;
}

static struct vmux_hub_peer *
vmux_hub_cache_get(struct vmux_hub *hub, uint64_t h)
{
    const struct vmux_hub_cache *c = __atomic_load_n(&hub->srccache, __ATOMIC_ACQUIRE);
    const uint64_t tag = h & ~UINT64_C(0xFFFFFFFF);
    const unsigned int i0 = (unsigned int)h & c->mask;

    for (unsigned int k = 0; k < 2; k++) {
        const uint64_t w = VMUX_ALOAD(&c->e[i0 ^ k]);

        if (!w || (w & ~UINT64_C(0xFFFFFFFF)) != tag)
            continue;

        const unsigned int idx = (unsigned int)(w & 0xFFFFFFFFU) - 1U;
        struct vmux_hub_peer *p = vmux_hub_peer_at(hub, idx);

        if (p && VMUX_ALOAD(&p->active))
            return p;
    }
    return NULL;
}

static void
vmux_hub_cache_put(struct vmux_hub *hub, uint64_t h, unsigned int idx)
{
    struct vmux_hub_cache *c = __atomic_load_n(&hub->srccache, __ATOMIC_ACQUIRE);
    const uint64_t tag = h & ~UINT64_C(0xFFFFFFFF);
    const uint64_t word = tag | (uint64_t)(idx + 1U);
    const unsigned int i0 = (unsigned int)h & c->mask;

    for (unsigned int k = 0; k < 2; k++) {
        const uint64_t w = VMUX_ALOAD(&c->e[i0 ^ k]);

        if (!w || (w & ~UINT64_C(0xFFFFFFFF)) == tag) {
            VMUX_ASTORE(&c->e[i0 ^ k], word);
            return;
        }
    }
    VMUX_ASTORE(&c->e[i0], word); /* evict */
}

static int
vmux_prefix_match(const struct vmux_prefix *p, int family,
                 const unsigned char *addr)
{
    if (p->family != family)
        return 0;

    const unsigned int bytes = p->len / 8U;
    const unsigned int bits = p->len % 8U;

    if (bytes && memcmp(p->addr, addr, bytes))
        return 0;

    if (bits) {
        const unsigned char mask = (unsigned char)(0xFFU << (8U - bits));

        if ((p->addr[bytes] ^ addr[bytes]) & mask)
            return 0;
    }
    return 1;
}

static int
vmux_prefix_valid(const struct vmux_prefix *p)
{
    if (p->family == AF_INET)
        return p->len <= 32;
    if (p->family == AF_INET6)
        return p->len <= 128;
    return 0;
}

static int
vmux_prefix_same(const struct vmux_prefix *a, const struct vmux_prefix *b)
{
    if (a->family != b->family || a->len != b->len)
        return 0;

    /* compare only the significant bits */
    struct vmux_prefix x = *a, y = *b;
    unsigned int bytes = a->len / 8U, bits = a->len % 8U;
    const size_t total = (a->family == AF_INET) ? 4U : 16U;

    if (bits) {
        const unsigned char mask = (unsigned char)(0xFFU << (8U - bits));

        x.addr[bytes] &= mask;
        y.addr[bytes] &= mask;
        bytes++;
    }
    if (bytes < total) {
        memset(x.addr + bytes, 0, total - bytes);
        memset(y.addr + bytes, 0, total - bytes);
    }
    return !memcmp(x.addr, y.addr, total);
}

/* Route index: finds the client that owns an inner destination address with a
 * few hash lookups instead of scanning every client's prefixes. One entry per
 * allowed prefix: the key is the family, length and masked address (see
 * vmux_rt_key()), the value the owning slot + 1 (0 = removed). Entries are
 * added and removed in place; readers take no lock (value is written before
 * the key, which is published with release ordering). A hit is always checked
 * against the client's real prefix list, so a hash collision cannot send a
 * packet to the wrong client. Which prefix lengths exist is kept in a bit set so
 * a lookup only tries those, longest first. */
struct vmux_hub_rtab {
    unsigned int mask;
    unsigned int used; /* entries ever filled in (dead ones included); admin only */
    uint64_t e[];
};

static uint64_t
vmux_rt_key(int family, unsigned int len, const unsigned char *addr)
{
    unsigned char m[16] = {0};
    const size_t total = (family == AF_INET) ? 4U : 16U;
    const unsigned int bytes = len / 8U, bits = len % 8U;

    memcpy(m, addr, total);

    if (bits)
        m[bytes] &= (unsigned char)(0xFFU << (8U - bits));

    for (size_t i = bytes + (bits ? 1U : 0U); i < total; i++)
        m[i] = 0;

    if (family == AF_INET) {
        uint32_t a;

        memcpy(&a, m, sizeof(a));
        return (UINT64_C(1) << 63) | ((uint64_t)len << 32) | a;
    }
    uint64_t h = vmux_hub_mix(UINT64_C(14695981039346656037) ^ len, m, sizeof(m));

    h ^= h >> 29;
    h *= UINT64_C(0xBF58476D1CE4E5B9);
    h ^= h >> 32;
    return (h & ~(UINT64_C(1) << 63)) | (UINT64_C(1) << 62);
}

static void
vmux_rt_count(struct vmux_hub *hub, int family, unsigned int len, int delta)
{
    const int f = (family == AF_INET) ? 0 : 1;
    uint64_t *w = &hub->rt_bits[f][len / 64U];
    uint64_t v = *w;

    hub->rt_cnt[f][len] += delta;

    if (hub->rt_cnt[f][len])
        v |= UINT64_C(1) << (len % 64U);
    else
        v &= ~(UINT64_C(1) << (len % 64U));

    __atomic_store_n(w, v, __ATOMIC_RELEASE);
}

static void
vmux_rt_insert(struct vmux_hub_rtab *t, uint64_t key, uint64_t value)
{
    unsigned int k = (unsigned int)key & t->mask;

    while (t->e[2 * k])
        k = (k + 1) & t->mask;

    __atomic_store_n(&t->e[2 * k + 1], value, __ATOMIC_RELAXED);
    __atomic_store_n(&t->e[2 * k], key, __ATOMIC_RELEASE);
    t->used++;
}

/* Rebuilds the route index from every active client's prefixes. Done when the
 * index is full; individual changes go through vmux_hub_rt_add/del. Caller
 * holds admin_lock. */
static void
vmux_hub_rt_rebuild(struct vmux_hub *hub)
{
    size_t total = 0;

    for (unsigned int i = 0; i < hub->peer_hwm; i++) {
        const struct vmux_hub_peer *p = vmux_hub_peer_at(hub, i);

        if (p->active && p->routes)
            total += p->routes->count;
    }
    size_t entries = 64;

    while (entries < total * 4)
        entries <<= 1;

    struct vmux_hub_rtab *t = calloc(1, sizeof(*t) + entries * 2 * sizeof(uint64_t));

    if (!t)
        return;

    t->mask = (unsigned int)(entries - 1);
    memset(hub->rt_cnt, 0, sizeof(hub->rt_cnt));

    for (unsigned int i = 0; i < hub->peer_hwm; i++) {
        const struct vmux_hub_peer *p = vmux_hub_peer_at(hub, i);

        if (!p->active || !p->routes)
            continue;

        for (unsigned int k = 0; k < p->routes->count; k++) {
            const struct vmux_prefix *x = &p->routes->prefix[k];

            vmux_rt_insert(t, vmux_rt_key(x->family, x->len, x->addr),
                           (uint64_t)p->index + 1U);
            hub->rt_cnt[x->family == AF_INET ? 0 : 1][x->len]++;
        }
    }
    for (int f = 0; f < 2; f++) {
        for (unsigned int w = 0; w < 3; w++) {
            uint64_t bits = 0;

            for (unsigned int b = 0; b < 64U; b++) {
                const unsigned int len = w * 64U + b;

                if (len <= 128U && hub->rt_cnt[f][len])
                    bits |= UINT64_C(1) << b;
            }
            __atomic_store_n(&hub->rt_bits[f][w], bits, __ATOMIC_RELEASE);
        }
    }
    struct vmux_hub_rtab *old = hub->rtab;

    __atomic_store_n(&hub->rtab, t, __ATOMIC_RELEASE);
    vmux_hub_retire(hub, old, VMUX_RETIRE_FREE, NULL);
}

/* Adds a client's current prefixes to the index. Caller holds admin_lock. */
static void
vmux_hub_rt_add(struct vmux_hub *hub, const struct vmux_hub_peer *p)
{
    struct vmux_hub_rtab *t = hub->rtab;
    const struct vmux_hub_routes *r = p->routes;

    if (!r || !r->count)
        return;

    if (!t || (size_t)(t->used + r->count) * 2U > (size_t)t->mask + 1U) {
        vmux_hub_rt_rebuild(hub); /* includes this client */
        return;
    }
    for (unsigned int k = 0; k < r->count; k++) {
        const struct vmux_prefix *x = &r->prefix[k];

        vmux_rt_insert(t, vmux_rt_key(x->family, x->len, x->addr),
                       (uint64_t)p->index + 1U);
        vmux_rt_count(hub, x->family, x->len, 1);
    }
}

/* Removes the prefixes `r` of a client from the index. Caller holds
 * admin_lock. */
static void
vmux_hub_rt_del(struct vmux_hub *hub, const struct vmux_hub_peer *p,
               const struct vmux_hub_routes *r)
{
    struct vmux_hub_rtab *t = hub->rtab;

    if (!t || !r)
        return;

    for (unsigned int i = 0; i < r->count; i++) {
        const struct vmux_prefix *x = &r->prefix[i];
        const uint64_t key = vmux_rt_key(x->family, x->len, x->addr);

        for (unsigned int k = (unsigned int)key & t->mask; t->e[2 * k];
             k = (k + 1) & t->mask) {
            if (t->e[2 * k] == key &&
                t->e[2 * k + 1] == (uint64_t)p->index + 1U) {
                __atomic_store_n(&t->e[2 * k + 1], 0, __ATOMIC_RELEASE);
                vmux_rt_count(hub, x->family, x->len, -1);
                break;
            }
        }
    }
}

/* Longest-prefix match of a packet's inner destination over every active
 * peer's allowed prefixes. NULL when nobody owns it. */
static struct vmux_hub_peer *
vmux_hub_route(struct vmux_hub *hub, const unsigned char *pkt, size_t size)
{
    int family;
    const unsigned char *dst;
    unsigned int f, words;

    if (size >= 20 && (pkt[0] >> 4) == 4) {
        family = AF_INET;
        dst = pkt + 16;
        f = 0;
        words = 1;
    } else if (size >= 40 && (pkt[0] >> 4) == 6) {
        family = AF_INET6;
        dst = pkt + 24;
        f = 1;
        words = 3;
    } else {
        return NULL;
    }
    const struct vmux_hub_rtab *t = __atomic_load_n(&hub->rtab, __ATOMIC_ACQUIRE);

    if (!t)
        return NULL;

    for (unsigned int w = words; w > 0; w--) {
        uint64_t bits = __atomic_load_n(&hub->rt_bits[f][w - 1U], __ATOMIC_ACQUIRE);

        while (bits) {
            const unsigned int b = 63U - (unsigned int)__builtin_clzll(bits);
            const unsigned int len = (w - 1U) * 64U + b;
            const uint64_t key = vmux_rt_key(family, len, dst);

            bits &= ~(UINT64_C(1) << b);

            for (unsigned int k = (unsigned int)key & t->mask;
                 __atomic_load_n(&t->e[2 * k], __ATOMIC_ACQUIRE);
                 k = (k + 1) & t->mask) {
                if (t->e[2 * k] != key)
                    continue;

                const uint64_t v = __atomic_load_n(&t->e[2 * k + 1], __ATOMIC_ACQUIRE);

                if (!v)
                    continue;

                struct vmux_hub_peer *p = vmux_hub_peer_at(hub, (unsigned int)(v - 1U));

                if (!p || !VMUX_ALOAD(&p->active))
                    continue;

                const struct vmux_hub_routes *r =
                    __atomic_load_n(&p->routes, __ATOMIC_ACQUIRE);

                for (unsigned int i = 0; r && i < r->count; i++) {
                    if (r->prefix[i].len == len &&
                        vmux_prefix_match(&r->prefix[i], family, dst))
                        return p;
                }
            }
        }
    }
    return NULL;
}

/* Anti-spoofing: the inner source of a packet received from `p` must be an
 * address `p` owns. Returns 1 if it does, 0 if it does not (spoofing), and -1
 * for traffic that is dropped but is not an attempt at anything: the
 * unspecified address and IPv6 link-local sources (neighbour discovery and
 * the like), which belong to the client's own end of the link. */
static int
vmux_hub_src_ok(struct vmux_hub_peer *p, const unsigned char *pkt, size_t size)
{
    int family;
    const unsigned char *src;

    if (size >= 20 && (pkt[0] >> 4) == 4) {
        family = AF_INET;
        src = pkt + 12;
    } else if (size >= 40 && (pkt[0] >> 4) == 6) {
        family = AF_INET6;
        src = pkt + 8;
    } else {
        return 0;
    }
    const struct vmux_hub_routes *r =
        __atomic_load_n(&p->routes, __ATOMIC_ACQUIRE);

    if (!r)
        return 0;

    if (family == AF_INET6 && ((src[0] == 0xFE && (src[1] & 0xC0) == 0x80) ||
                               !memcmp(src, (const unsigned char[16]){0}, 16)))
        return -1;
    if (family == AF_INET && !memcmp(src, (const unsigned char[4]){0}, 4))
        return -1;

    for (unsigned int k = 0; k < r->count; k++) {
        if (vmux_prefix_match(&r->prefix[k], family, src))
            return 1;
    }
    return 0;
}

static struct vmux_hub_peer *
vmux_hub_find(struct vmux_hub *hub, const char *name)
{
    const unsigned int n = __atomic_load_n(&hub->peer_hwm, __ATOMIC_ACQUIRE);

    for (unsigned int i = 0; i < n; i++) {
        if (vmux_hub_peer_at(hub, i)->used && !strcmp(vmux_hub_peer_at(hub, i)->name, name))
            return vmux_hub_peer_at(hub, i);
    }
    return NULL;
}

static int
vmux_hub_name_valid(const char *name)
{
    if (!name || !name[0] || strlen(name) >= VMUX_HUB_NAME_MAX)
        return 0;

    for (const char *c = name; *c; c++) {
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
              (*c >= '0' && *c <= '9') || *c == '_' || *c == '-' ||
              *c == '.'))
            return 0;
    }
    return 1;
}

/* Builds an immutable route snapshot. The previous one is parked in
 * the retired list (workers may still be reading it) and freed later.
 * Caller holds admin_lock. */
static struct vmux_hub_routes *
vmux_hub_routes_new(struct vmux_hub *hub, const struct vmux_prefix *allowed,
                   unsigned int count)
{
    struct vmux_hub_routes *r = calloc(1, sizeof(*r));

    if (!r)
        return NULL;

    r->count = count;
    if (count)
        memcpy(r->prefix, allowed, count * sizeof(*allowed));

    return r;
}

/* Rejects a prefix list that is invalid or that duplicates a prefix some
 * *other* active peer already owns. Caller holds admin_lock. */
static int
vmux_hub_check_allowed(struct vmux_hub *hub, const struct vmux_hub_peer *self,
                      const struct vmux_prefix *allowed, unsigned int count)
{
    if (count > VMUX_HUB_ALLOWED_MAX || (count && !allowed))
        return EINVAL;

    for (unsigned int k = 0; k < count; k++) {
        if (!vmux_prefix_valid(&allowed[k]))
            return EINVAL;

        for (unsigned int j = k + 1; j < count; j++) {
            if (vmux_prefix_same(&allowed[k], &allowed[j]))
                return EINVAL;
        }
    }
    /* is any of these prefixes already owned by another client? One lookup in
     * the route index each, not a scan of every client. */
    const struct vmux_hub_rtab *t = hub->rtab;

    if (!t)
        return 0;

    for (unsigned int k = 0; k < count; k++) {
        const uint64_t key = vmux_rt_key(allowed[k].family, allowed[k].len,
                                         allowed[k].addr);

        for (unsigned int j = (unsigned int)key & t->mask; t->e[2 * j];
             j = (j + 1) & t->mask) {
            if (t->e[2 * j] != key || !t->e[2 * j + 1])
                continue;

            const struct vmux_hub_peer *p =
                vmux_hub_peer_at(hub, (unsigned int)(t->e[2 * j + 1] - 1U));

            if (!p || p == self || !p->active || !p->routes)
                continue;

            for (unsigned int a = 0; a < p->routes->count; a++) {
                if (vmux_prefix_same(&p->routes->prefix[a], &allowed[k]))
                    return EADDRINUSE;
            }
        }
    }
    return 0;
}

static void
vmux_policy_merge(struct vmux_policy *dst, const struct vmux_policy *src)
{
    if (src->set & VMUX_POLICY_TX_RATE)   dst->tx_max_rate = src->tx_max_rate;
    if (src->set & VMUX_POLICY_RX_RATE)   dst->rx_max_rate = src->rx_max_rate;
    if (src->set & VMUX_POLICY_MTU)       dst->mtu         = src->mtu;
    if (src->set & VMUX_POLICY_PREF)      dst->pref        = src->pref;
    if (src->set & VMUX_POLICY_LOSSLIMIT) dst->loss_limit  = src->loss_limit;
    if (src->set & VMUX_POLICY_RTTLIMIT)  dst->rtt_limit   = src->rtt_limit;
    if (src->set & VMUX_POLICY_MAXPATHS)  dst->max_paths   = src->max_paths;
    dst->set |= src->set;
}

/* A fresh independent session that shares the hub's sockets. */
static struct vmux *
vmux_hub_session_new(struct vmux_hub *hub, const unsigned char *key)
{
    struct vmux *vmux = vmux_pool_alloc();

    if (!vmux)
        return NULL;

    vmux->pooled = 1;
    vmux->borrowed_socks = 1;

    if (pthread_mutex_init(&vmux->state_lock, NULL))
        goto err0;
    if (pthread_mutex_init(&vmux->keyx_lock, NULL))
        goto err1;
    if (pthread_mutex_init(&vmux->reorder.lock, NULL))
        goto err2;
    if (pthread_mutex_init(&vmux->reorder.flush_lock, NULL))
        goto err3;

    vmux->capacity = 0;
    vmux->path_limit = VMUX_PATH_UNLIMITED;

    for (unsigned int i = 0; i < hub->sock_count; i++)
        vmux->sock[i] = hub->sock[i];

    vmux->sock_count = hub->sock_count;
    vmux->sock_v4 = hub->sock_v4;
    vmux->sock_v6 = hub->sock_v6;
    vmux->sock_family = hub->sock_family;
    vmux->passive_pool_size = 0; /* no per-session socket promotion in a hub */
    vmux->conf = hub->defaults;

#if defined __APPLE__
    mach_timebase_info(&vmux->mtid);
#endif
    {
        const uint64_t now = vmux_now(vmux);
        const uint64_t base_time = vmux_time();

        if (base_time > now)
            vmux->base_time = base_time - now;
    }
    memcpy(vmux->keyx.private.encrypt.key, key, VMUX_KEY_SIZE);
    memcpy(vmux->keyx.private.decrypt.key, key, VMUX_KEY_SIZE);
    vmux_id_init(vmux, key);
    vmux->keyx.current = vmux->keyx.private;
    vmux->keyx.next = vmux->keyx.private;
    vmux->keyx.last = vmux->keyx.private;
    vmux->keyx.aes = hub->aes;

    /* Generate this session's key pair now, not on the first housekeeping tick.
     * A hub starts its workers with datagrams already queued on the sockets
     * (clients keep beating while the server is down), so a worker can answer
     * a control message before the first tick -- with an all-zero public key,
     * which the client rejects, and a key derived from an all-zero secret on
     * this side. Clients that happened to beat in lockstep then all stuck on
     * wrong keys at once. */
    pthread_mutex_lock(&vmux->state_lock);
    vmux_keyx_init(vmux, vmux_now(vmux));
    pthread_mutex_unlock(&vmux->state_lock);
    return vmux;

err3:
    pthread_mutex_destroy(&vmux->reorder.lock);
err2:
    pthread_mutex_destroy(&vmux->keyx_lock);
err1:
    pthread_mutex_destroy(&vmux->state_lock);
err0:
    vmux_pool_free(vmux);
    return NULL;
}

struct vmux_hub *
vmux_hub_create(union vmux_sockaddr *addr, int *aes)
{
    if (!addr || !aes)
        return NULL;

    int v4, v6;
    socklen_t addrlen = 0;

    switch (addr->sa.sa_family) {
    case AF_INET:
        addrlen = sizeof(struct sockaddr_in);
        v4 = 1;
        v6 = 0;
        break;
    case AF_INET6:
        addrlen = sizeof(struct sockaddr_in6);
        v4 = VMUX_V4V6;
        v6 = 1;
        break;
    default:
        return NULL;
    }
    if (sodium_init() == -1)
        return NULL;

    struct vmux_hub *hub = calloc(1, sizeof(*hub));

    if (!hub)
        return NULL;

    if (pthread_mutex_init(&hub->admin_lock, NULL)) {
        free(hub);
        return NULL;
    }
    hub->chunk = calloc(VMUX_HUB_CHUNKS_MAX, sizeof(*hub->chunk));
    hub->chunk_dirty = calloc(2U * VMUX_HUB_CHUNKS_MAX, sizeof(*hub->chunk_dirty));
    hub->srccache = calloc(1, sizeof(*hub->srccache) +
                              VMUX_HUB_SRC_CACHE_MIN * sizeof(uint64_t));

    if (!hub->chunk || !hub->chunk_dirty || !hub->srccache) {
        free(hub->chunk);
        free(hub->chunk_dirty);
        free(hub->srccache);
        pthread_mutex_destroy(&hub->admin_lock);
        free(hub);
        return NULL;
    }
    hub->srccache->mask = VMUX_HUB_SRC_CACHE_MIN - 1U;
    const int fd0 = socket(addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

    if ((fd0 == -1) ||
        (vmux_setup_socket(fd0, v4, v6)) ||
        (bind(fd0, &addr->sa, addrlen)) ||
        (getsockname(fd0, &addr->sa, &addrlen))) {
        if (fd0 != -1)
            close(fd0);
        free(hub->chunk);
        free(hub->chunk_dirty);
        free(hub->srccache);
        pthread_mutex_destroy(&hub->admin_lock);
        free(hub);
        return NULL;
    }
    hub->sock[0] = fd0;
    hub->sock_count = 1;
    hub->sock_v4 = v4;
    hub->sock_v6 = v6;
    hub->sock_family = addr->sa.sa_family;

    /* Same SO_REUSEPORT receive-scaling pool vmux_create() opens (see its
     * long comment): every socket bound to the same resolved port, so the
     * kernel spreads inbound flows across the worker threads. */
    const unsigned int want_unclamped = vmux_worker_count() * VMUX_REUSEPORT_SCALE;
    const unsigned int want = (want_unclamped > VMUX_SOCK_MAX / 4)
                             ? VMUX_SOCK_MAX / 4 : want_unclamped;

    while (hub->sock_count < want) {
        const int fd = socket(addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

        if ((fd == -1) ||
            (vmux_setup_socket(fd, v4, v6)) ||
            (bind(fd, &addr->sa, addrlen))) {
            if (fd != -1)
                close(fd);
            break;
        }
        hub->sock[hub->sock_count++] = fd;
    }
    for (unsigned int i = 0; i < hub->sock_count; i++) {
        const int fl = fcntl(hub->sock[i], F_GETFL, 0);

        if (fl != -1)
            fcntl(hub->sock[i], F_SETFL, fl | O_NONBLOCK);
    }
    hub->defaults.keepalive     = 25 * VMUX_ONE_SEC;
    hub->defaults.timetolerance = 10 * VMUX_ONE_MIN;
    hub->defaults.kxtimeout     = 60 * VMUX_ONE_MIN;
    hub->defaults.strict_order  = 1;
    hub->defaults.tx_batch      = VMUX_TX_BATCH_DEFAULT;

    if (*aes && !aegis256_is_available())
        *aes = 0;

    hub->aes = *aes;
    return hub;
}

void
vmux_hub_delete(struct vmux_hub *hub)
{
    if (!hub)
        return;

    /* sessions parked for removal first, then what each slot still points at */
    for (unsigned int i = 0; i < hub->retired_count; i++) {
        struct vmux_hub_retired *e = &hub->retired[i];

        if (e->kind == VMUX_RETIRE_SESSION) {
            if (e->slot)
                e->slot->vmux = NULL;
            vmux_delete(e->ptr);
        } else {
            free(e->ptr);
        }
    }
    free(hub->retired);
    free(hub->free_slots);

    for (unsigned int i = 0; i < hub->peer_hwm; i++) {
        struct vmux_hub_peer *p = vmux_hub_peer_at(hub, i);

        if (p->vmux)
            vmux_delete(p->vmux);
        free(p->routes);
        free(p->q);
        pthread_mutex_destroy(&p->q_lock);
        pthread_mutex_destroy(&p->rx_lock);
    }
    for (unsigned int c = 0; c < VMUX_HUB_CHUNKS_MAX && hub->chunk[c]; c++)
        free(hub->chunk[c]);

    free(hub->idtab);
    free(hub->rtab);
    free(hub->srccache);
    free(hub->chunk_dirty);
    free(hub->chunk);

    for (unsigned int i = 0; i < hub->sock_count; i++) {
        if (hub->sock[i] >= 0)
            close(hub->sock[i]);
    }
    pthread_mutex_destroy(&hub->admin_lock);
    free(hub);
}

/* Whether an active client already uses this key. The identifier a key gives
 * for the table's current window is looked up, and only the clients it points to
 * have their key compared; no scan of every client. */
static int
vmux_hub_key_in_use(struct vmux_hub *hub, const unsigned char *key)
{
    const struct vmux_hub_idtab *t = hub->idtab;
    unsigned char idkey[VMUX_KEY_SIZE], id[VMUX_ID_SIZE];

    if (!t)
        return 0;

    vmux_id_derive(idkey, key);
    vmux_id_compute(idkey, t->window, id);
    sodium_memzero(idkey, sizeof(idkey));

    const uint64_t want = vmux_id_key(id);

    for (unsigned int k = (unsigned int)want & t->mask; t->e[2 * k];
         k = (k + 1) & t->mask) {
        if (t->e[2 * k] != want || !t->e[2 * k + 1])
            continue;

        const struct vmux_hub_peer *p =
            vmux_hub_peer_at(hub, (unsigned int)(t->e[2 * k + 1] - 1U));

        if (p && p->active && p->vmux &&
            !sodium_memcmp(p->vmux->keyx.private.encrypt.key, key, VMUX_KEY_SIZE))
            return 1;
    }
    return 0;
}

/* Allocates chunk `c` of peer slots (see VMUX_HUB_CHUNK_BITS). Caller holds
 * admin_lock. Returns 0 or an errno value. */
static int
vmux_hub_chunk_add(struct vmux_hub *hub, unsigned int c)
{
    if (c >= VMUX_HUB_CHUNKS_MAX)
        return ENOSPC;

    struct vmux_hub_peer *ch = calloc(VMUX_HUB_CHUNK, sizeof(*ch));

    if (!ch)
        return ENOMEM;

    for (unsigned int i = 0; i < VMUX_HUB_CHUNK; i++) {
        ch[i].index = (c << VMUX_HUB_CHUNK_BITS) + i;
        ch[i].hub = hub;
        pthread_mutex_init(&ch[i].q_lock, NULL);
        pthread_mutex_init(&ch[i].rx_lock, NULL);
    }
    __atomic_store_n(&hub->chunk[c], ch, __ATOMIC_RELEASE);
    return 0;
}

int
vmux_hub_peer_add(struct vmux_hub *hub, const char *name,
                 const unsigned char *key,
                 const struct vmux_prefix *allowed, unsigned int count,
                 const struct vmux_policy *policy)
{
    if (!hub || !key || !vmux_hub_name_valid(name)) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&hub->admin_lock);

    struct vmux_hub_peer *slot = vmux_hub_find(hub, name);
    int err = 0;

    if (slot && slot->active) {
        err = EEXIST;
        goto out;
    }
    if ((err = vmux_hub_check_allowed(hub, slot, allowed, count)))
        goto out;

    /* One pre-shared key per client: it is what identifies a roaming or
     * newly-appeared source as belonging to this client, so two clients
     * sharing one would be indistinguishable. */
    if (vmux_hub_key_in_use(hub, key)) {
        err = EKEYREJECTED;
        goto out;
    }
    /* Where the client will live: its old slot (a removed client coming
     * back), a slot freed by a removed client, or a new one. The room for a
     * new one is made now, before anything else can fail. */
    unsigned int new_index = 0;

    if (!slot && !hub->free_count) {
        new_index = hub->peer_hwm;

        if (!vmux_hub_peer_at(hub, new_index) &&
            (err = vmux_hub_chunk_add(hub, new_index >> VMUX_HUB_CHUNK_BITS)))
            goto out;
    }
    struct vmux *vmux = vmux_hub_session_new(hub, key);

    if (!vmux) {
        err = ENOMEM;
        goto out;
    }
    if (policy && vmux_set_policy(vmux, policy)) {
        err = errno;
        vmux_delete(vmux);
        goto out;
    }
    struct vmux_hub_routes *routes = vmux_hub_routes_new(hub, allowed, count);

    if (!routes) {
        vmux_delete(vmux);
        err = ENOMEM;
        goto out;
    }
    if (slot) {
        /* A removed client coming back: its old session is already parked
         * for removal; the old route snapshot is parked now. */
        vmux_hub_retire(hub, slot->routes, VMUX_RETIRE_FREE, NULL);
    } else if (hub->free_count) {
        slot = vmux_hub_peer_at(hub, hub->free_slots[--hub->free_count]);
        memcpy(slot->name, name, strlen(name) + 1);
        slot->used = 1;
    } else {
        slot = vmux_hub_peer_at(hub, new_index);
        memcpy(slot->name, name, strlen(name) + 1);
        slot->used = 1;
    }
    VMUX_ASTORE(&slot->tx_mtu, 0);
    VMUX_ASTORE(&slot->tx_drop_rate, 0);
    VMUX_ASTORE(&slot->tx_drop_mtu, 0);
    VMUX_ASTORE(&slot->rx_drop_spoof, 0);
    VMUX_ASTORE(&slot->rx_drop_rate, 0);
    __atomic_store_n(&slot->vmux, vmux, __ATOMIC_RELEASE);
    __atomic_store_n(&slot->routes, routes, __ATOMIC_RELEASE);

    if (slot->index >= hub->peer_hwm)
        __atomic_store_n(&hub->peer_hwm, slot->index + 1U, __ATOMIC_RELEASE);

    __atomic_store_n(&slot->active, 1, __ATOMIC_RELEASE);
    vmux_hub_cache_grow(hub);
    vmux_hub_id_add(hub, slot);
    vmux_hub_rt_add(hub, slot);
out:
    pthread_mutex_unlock(&hub->admin_lock);
    if (err) {
        errno = err;
        return -1;
    }
    return 0;
}

int
vmux_hub_peer_set(struct vmux_hub *hub, const char *name,
                 const struct vmux_prefix *allowed, int allowed_set,
                 unsigned int allowed_count,
                 const struct vmux_policy *set, unsigned int unset,
                 struct vmux_conf *conf)
{
    if (!hub || !name) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&hub->admin_lock);

    struct vmux_hub_peer *p = vmux_hub_find(hub, name);
    int err = 0;

    if (!p || !p->active) {
        err = ENOENT;
        goto out;
    }
    if (allowed_set) {
        if ((err = vmux_hub_check_allowed(hub, p, allowed, allowed_count)))
            goto out;

        struct vmux_hub_routes *r =
            vmux_hub_routes_new(hub, allowed, allowed_count);

        if (!r) {
            err = ENOMEM;
            goto out;
        }
        struct vmux_hub_routes *old_routes = p->routes;

        vmux_hub_rt_del(hub, p, old_routes);
        __atomic_store_n(&p->routes, r, __ATOMIC_RELEASE);
        vmux_hub_rt_add(hub, p);
        vmux_hub_retire(hub, old_routes, VMUX_RETIRE_FREE, NULL);
    }
    if (set || unset) {
        struct vmux_policy cur;

        vmux_get_policy(p->vmux, &cur);
        if (set)
            vmux_policy_merge(&cur, set);
        cur.set &= ~unset;

        if (vmux_set_policy(p->vmux, &cur)) {
            err = errno;
            goto out;
        }
    }
    if (conf && vmux_set(p->vmux, conf))
        err = errno;
out:
    pthread_mutex_unlock(&hub->admin_lock);
    if (err) {
        errno = err;
        return -1;
    }
    return 0;
}

int
vmux_hub_peer_del(struct vmux_hub *hub, const char *name)
{
    if (!hub || !name) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&hub->admin_lock);

    struct vmux_hub_peer *p = vmux_hub_find(hub, name);
    int err = 0;

    if (!p || !p->active) {
        err = ENOENT;
    } else {
        __atomic_store_n(&p->active, 0, __ATOMIC_RELEASE);
        vmux_hub_id_del(hub, p);
        vmux_hub_rt_del(hub, p, p->routes);
        /* workers may still be using the session for a moment: it is freed
         * (and the slot made reusable) after a while, by vmux_hub_reap() */
        vmux_hub_retire(hub, p->vmux, VMUX_RETIRE_SESSION, p);
    }

    pthread_mutex_unlock(&hub->admin_lock);
    if (err) {
        errno = err;
        return -1;
    }
    return 0;
}

struct vmux *
vmux_hub_peer_get(struct vmux_hub *hub, const char *name)
{
    struct vmux_hub_peer *p = hub ? vmux_hub_find(hub, name) : NULL;

    if (!p || !VMUX_ALOAD(&p->active))
        return NULL;

    return __atomic_load_n(&p->vmux, __ATOMIC_ACQUIRE);
}

unsigned int
vmux_hub_peer_count(struct vmux_hub *hub)
{
    return hub ? __atomic_load_n(&hub->peer_hwm, __ATOMIC_ACQUIRE) : 0;
}

int
vmux_hub_peer_info(struct vmux_hub *hub, unsigned int slot,
                  struct vmux_hub_peer_info *info)
{
    if (!hub || !info || slot >= vmux_hub_peer_count(hub)) {
        errno = EINVAL;
        return -1;
    }
    struct vmux_hub_peer *p = vmux_hub_peer_at(hub, slot);
    struct vmux *vmux = __atomic_load_n(&p->vmux, __ATOMIC_ACQUIRE);

    memset(info, 0, sizeof(*info));
    memcpy(info->name, p->name, sizeof(info->name));
    info->active = VMUX_ALOAD(&p->active);

    const struct vmux_hub_routes *r =
        __atomic_load_n(&p->routes, __ATOMIC_ACQUIRE);

    if (r) {
        info->allowed_count = r->count;
        memcpy(info->allowed, r->prefix, r->count * sizeof(r->prefix[0]));
    }
    if (vmux) {
        pthread_mutex_lock(&vmux->state_lock);
        info->policy = vmux->policy;
        info->conf = vmux->conf;
        for (unsigned int i = 0; i < vmux->capacity; i++) {
            if (vmux_path_at(vmux, i)->conf.state != VMUX_EMPTY)
                info->path_count++;
        }
        pthread_mutex_unlock(&vmux->state_lock);
        info->mtu = vmux_get_mtu(vmux);
    }
    info->tx_drop_rate  = VMUX_ALOAD(&p->tx_drop_rate);
    info->tx_drop_mtu   = VMUX_ALOAD(&p->tx_drop_mtu);
    info->rx_drop_spoof = VMUX_ALOAD(&p->rx_drop_spoof);
    info->rx_drop_rate  = VMUX_ALOAD(&p->rx_drop_rate);
    return 0;
}

/* Defaults for peers added from now on; existing peers are not touched. */
void
vmux_hub_set_defaults(struct vmux_hub *hub, struct vmux_conf *conf)
{
    pthread_mutex_lock(&hub->admin_lock);
    if (conf->keepalive)     hub->defaults.keepalive     = conf->keepalive;
    if (conf->timetolerance) hub->defaults.timetolerance = conf->timetolerance;
    if (conf->kxtimeout)     hub->defaults.kxtimeout     = conf->kxtimeout;
    if (conf->reorder_window)
        hub->defaults.reorder_window = conf->reorder_window >> 1;
    if (conf->strict_order)
        hub->defaults.strict_order = conf->strict_order == 2;
    /* one value for the whole hub: its workers read it on every TX wakeup */
    if (conf->tx_batch)
        VMUX_ASTORE(&hub->defaults.tx_batch,
                    conf->tx_batch > VMUX_TX_BATCH_MAX ? VMUX_TX_BATCH_MAX
                                                       : conf->tx_batch);
    *conf = hub->defaults;
    pthread_mutex_unlock(&hub->admin_lock);
}

void
vmux_hub_get_stats(struct vmux_hub *hub, struct vmux_hub_stats *st)
{
    st->tx_drop_noroute = VMUX_ALOAD(&hub->tx_drop_noroute);
    st->rx_drop_unknown = VMUX_ALOAD(&hub->rx_drop_unknown);
    st->rx_drop_limited = VMUX_ALOAD(&hub->rx_drop_limited);
}

int
vmux_hub_update(struct vmux_hub *hub)
{
    /* the identifiers change every VMUX_ID_WINDOW: renew the table when the
     * window has moved on */
    const struct vmux_hub_idtab *t = __atomic_load_n(&hub->idtab, __ATOMIC_ACQUIRE);

    pthread_mutex_lock(&hub->admin_lock);
    if (!t || t->window != vmux_id_window(vmux_time()))
        vmux_hub_idtab_rebuild(hub);
    vmux_hub_reap(hub);
    pthread_mutex_unlock(&hub->admin_lock);
    const unsigned int n = vmux_hub_peer_count(hub);

    for (unsigned int i = 0; i < n; i++) {
        struct vmux_hub_peer *p = vmux_hub_peer_at(hub, i);

        if (!VMUX_ALOAD(&p->active))
            continue;

        struct vmux *vmux = __atomic_load_n(&p->vmux, __ATOMIC_ACQUIRE);

        /* a client that has never had a path has nothing to update; without
         * this every idle registered client would cost a little on each pass */
        if (!__atomic_load_n(&vmux->capacity, __ATOMIC_RELAXED))
            continue;

        vmux_update(vmux);
        VMUX_ASTORE(&p->tx_mtu, vmux_get_mtu(vmux));
    }
    return 0;
}

/* The largest inner packet any peer can take: a peer with a smaller MTU
 * must never shrink everyone else's, so this is a maximum, not a minimum --
 * packets too big for a given peer are answered per packet instead (see
 * vmux_hub_oversize_fn). */
size_t
vmux_hub_get_mtu(struct vmux_hub *hub)
{
    const unsigned int n = vmux_hub_peer_count(hub);
    size_t mtu = 0;

    for (unsigned int i = 0; i < n; i++) {
        const struct vmux_hub_peer *p = vmux_hub_peer_at(hub, i);
        const size_t m = VMUX_ALOAD(&p->tx_mtu);

        if (VMUX_ALOAD(&p->active) && m > mtu)
            mtu = m;
    }
    return mtu;
}

unsigned int
vmux_hub_get_sock_count(struct vmux_hub *hub)
{
    return hub ? hub->sock_count : 0;
}

int
vmux_hub_get_fd(struct vmux_hub *hub, unsigned int sock)
{
    return (hub && sock < hub->sock_count) ? hub->sock[sock] : -1;
}

/* Rebuilds the identifier table from scratch for every active client and
 * publishes it. Done when the time window moves on (the identifiers of every
 * client change) and when the table has filled up; adding or removing one
 * client only touches that client's entries (vmux_hub_id_add/del). The table
 * holds the identifiers for the windows around the current one (as many as the
 * clock tolerance allows), so a client whose clock is a few minutes off is
 * still found. Caller holds admin_lock. */
static void
vmux_hub_idtab_rebuild(struct vmux_hub *hub)
{
    const uint64_t centre = vmux_id_window(vmux_time());
    uint64_t span = hub->defaults.timetolerance / VMUX_ID_WINDOW + 1;

    if (span > 20)
        span = 20;

    const unsigned int windows = (unsigned int)(2 * span + 1);
    size_t active = 0;

    for (unsigned int i = 0; i < hub->peer_hwm; i++) {
        if (vmux_hub_peer_at(hub, i)->active)
            active++;
    }
    /* room to grow: it is rebuilt when it passes half full */
    size_t entries = 16;

    while (entries < (active ? active : 1) * windows * 4)
        entries <<= 1;

    struct vmux_hub_idtab *t = calloc(1, sizeof(*t) + entries * 2 * sizeof(uint64_t));

    if (!t)
        return; /* keep the current table; the next change tries again */

    t->mask = (unsigned int)(entries - 1);
    t->window = centre;
    t->span = (unsigned int)span;

    for (unsigned int i = 0; i < hub->peer_hwm; i++) {
        const struct vmux_hub_peer *p = vmux_hub_peer_at(hub, i);

        if (!p->active || !p->vmux)
            continue;

        for (unsigned int w = 0; w < windows; w++) {
            unsigned char id[VMUX_ID_SIZE];

            vmux_id_compute(p->vmux->idkey, centre - span + w, id);

            const uint64_t key = vmux_id_key(id);
            unsigned int k = (unsigned int)key & t->mask;

            while (t->e[2 * k])
                k = (k + 1) & t->mask;

            t->e[2 * k] = key;
            t->e[2 * k + 1] = (uint64_t)i + 1;
            t->used++;
        }
    }
    struct vmux_hub_idtab *old = hub->idtab;

    __atomic_store_n(&hub->idtab, t, __ATOMIC_RELEASE);
    vmux_hub_retire(hub, old, VMUX_RETIRE_FREE, NULL);
}

/* Adds one client's identifiers to the published table in place. A reader sees
 * an entry only once both of its words are written (value first, then the key
 * with release ordering). Caller holds admin_lock; the client is already
 * active. */
static void
vmux_hub_id_add(struct vmux_hub *hub, const struct vmux_hub_peer *p)
{
    struct vmux_hub_idtab *t = hub->idtab;

    if (!t || (size_t)(t->used + 2U * t->span + 1U) * 2U > (size_t)t->mask + 1U) {
        vmux_hub_idtab_rebuild(hub);
        return;
    }
    for (unsigned int w = 0; w <= 2U * t->span; w++) {
        unsigned char id[VMUX_ID_SIZE];

        vmux_id_compute(p->vmux->idkey, t->window - t->span + w, id);

        const uint64_t key = vmux_id_key(id);
        unsigned int k = (unsigned int)key & t->mask;

        while (t->e[2 * k])
            k = (k + 1) & t->mask;

        __atomic_store_n(&t->e[2 * k + 1], (uint64_t)p->index + 1U, __ATOMIC_RELAXED);
        __atomic_store_n(&t->e[2 * k], key, __ATOMIC_RELEASE);
        t->used++;
    }
}

/* Removes one client's identifiers from the published table: the entries stay
 * as dead slots (value 0) until the next rebuild. Caller holds admin_lock. */
static void
vmux_hub_id_del(struct vmux_hub *hub, const struct vmux_hub_peer *p)
{
    struct vmux_hub_idtab *t = hub->idtab;

    if (!t || !p->vmux)
        return;

    for (unsigned int w = 0; w <= 2U * t->span; w++) {
        unsigned char id[VMUX_ID_SIZE];

        vmux_id_compute(p->vmux->idkey, t->window - t->span + w, id);

        const uint64_t key = vmux_id_key(id);

        for (unsigned int k = (unsigned int)key & t->mask; t->e[2 * k];
             k = (k + 1) & t->mask) {
            if (t->e[2 * k] == key &&
                t->e[2 * k + 1] == (uint64_t)p->index + 1U) {
                __atomic_store_n(&t->e[2 * k + 1], 0, __ATOMIC_RELEASE);
                break;
            }
        }
    }
}

/* Finds which client a control message from a not-yet-known source belongs
 * to. The message ends with a client identifier, which is looked up in the
 * identifier table; only the client(s) it points to are tried for the real
 * check, the decryption with that client's key. Rate-limited so a flood of junk
 * from unknown addresses cannot turn into unbounded crypto work. */
static struct vmux_hub_peer *
vmux_hub_identify(struct vmux_hub *hub, const unsigned char *packet,
                 size_t size, unsigned char *scratch, size_t cap)
{
    const uint64_t sec = vmux_time() / VMUX_ONE_SEC;
    uint64_t cur = VMUX_ALOAD(&hub->ident_sec);

    if (cur != sec &&
        __atomic_compare_exchange_n(&hub->ident_sec, &cur, sec, 0,
                                    __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        VMUX_ASTORE(&hub->ident_count, 0);

    if (__atomic_fetch_add(&hub->ident_count, 1, __ATOMIC_RELAXED) >=
        VMUX_HUB_IDENT_PER_SEC) {
        VMUX_AINC(&hub->rx_drop_limited);
        return NULL;
    }
    if (size < VMUX_PKT_MIN_SIZE + VMUX_ID_SIZE)
        return NULL;

    const struct vmux_hub_idtab *t = __atomic_load_n(&hub->idtab, __ATOMIC_ACQUIRE);

    if (!t)
        return NULL;

    const uint64_t key = vmux_id_key(packet + size - VMUX_ID_SIZE);

    for (unsigned int k = (unsigned int)key & t->mask;
         __atomic_load_n(&t->e[2 * k], __ATOMIC_ACQUIRE);
         k = (k + 1) & t->mask) {
        if (t->e[2 * k] != key)
            continue;

        const uint64_t v = __atomic_load_n(&t->e[2 * k + 1], __ATOMIC_ACQUIRE);

        if (!v)
            continue; /* removed */

        const uint64_t slot = v - 1;

        struct vmux_hub_peer *p = (slot < UINT_MAX) ? vmux_hub_peer_at(hub, (unsigned int)slot) : NULL;

        if (!p || !VMUX_ALOAD(&p->active))
            continue;

        struct vmux *vmux = __atomic_load_n(&p->vmux, __ATOMIC_ACQUIRE);

        if (vmux_decrypt_msg(vmux, scratch, cap, packet, size - VMUX_ID_SIZE))
            return p;
    }
    return NULL;
}

static void
vmux_hub_flush_all(struct vmux_hub *hub, int tun_fd, vmux_tun_write_fn tun_write)
{
    unsigned int cur = 0;
    struct vmux_hub_peer *p;

    while ((p = vmux_hub_dirty_next(hub, VMUX_HUB_DIRTY_REORDER, &cur))) {
        if (!vmux_hub_unmark(hub, p, VMUX_HUB_DIRTY_REORDER))
            continue;

        if (!VMUX_ALOAD(&p->active))
            continue;

        struct vmux *vmux = __atomic_load_n(&p->vmux, __ATOMIC_ACQUIRE);

        if (VMUX_ALOAD(&vmux->conf.reorder_window)) {
            vmux_reorder_flush(vmux, tun_fd, tun_write);
            vmux_seq_flush(vmux, tun_fd, tun_write);
        }
        /* look again: whatever is still buffered has to be flushed later */
        if (vmux_hub_reorder_pending(vmux))
            vmux_hub_mark(hub, p, VMUX_HUB_DIRTY_REORDER);
    }
}

static int
vmux_hub_poll_timeout(struct vmux_hub *hub, int idle_ms)
{
    int timeout = idle_ms;
    unsigned int cur = 0;
    struct vmux_hub_peer *p;

    while ((p = vmux_hub_dirty_next(hub, VMUX_HUB_DIRTY_REORDER, &cur))) {
        if (!VMUX_ALOAD(&p->active))
            continue;

        struct vmux *vmux = __atomic_load_n(&p->vmux, __ATOMIC_ACQUIRE);

        if (VMUX_ALOAD(&vmux->conf.reorder_window))
            timeout = vmux_reorder_poll_timeout(vmux, timeout);
    }
    /* packets are waiting for tokens: look again in a millisecond */
    cur = 0;
    if (timeout > 1 && vmux_hub_dirty_next(hub, VMUX_HUB_DIRTY_Q, &cur))
        timeout = 1;
    return timeout;
}

/* ------------------------------------------------------------------------
 * Per-client shaping queue.
 *
 * The single-client loop enforces its rate by simply not reading the TUN
 * while the window is empty: the kernel queues the backlog and TCP is
 * back-pressured without losing packets. A hub cannot do that -- another
 * client may be ready on the same TUN -- and dropping whatever is over
 * budget (a plain policer) hits TCP with whole bursts of loss at once,
 * which ends in retransmission timeouts and a fraction of the configured
 * rate. Instead a packet that is over its client's budget waits in that
 * client's own short FIFO and is released as tokens arrive; only a full
 * queue drops, and the queue is bounded in *time* (about 125ms of the
 * client's rate), so shaping never turns into bufferbloat. The queue is
 * allocated the first time a client actually exceeds its rate.
 * ------------------------------------------------------------------------ */

struct vmux_hub_q {
    unsigned int head, count;
    size_t bytes;
    uint16_t len[VMUX_HUB_QLEN];
    unsigned char data[VMUX_HUB_QLEN][VMUX_HUB_QSLOT];
};

/* Charges `bytes` against the client's rate window and says whether the packet
 * may go. The charge is made *here*, atomically with the check: the
 * single-client loop checks first and pays later (when the send completes),
 * which is only safe because it sends one small batch at a time. With several
 * workers all checking the same window before any of them has paid, they all
 * pass and the client gets a multiple of its rate. The window is also topped
 * up first, so the limiter is a smooth token bucket rather than one that
 * receives a whole 100ms tick of tokens at once. A packet larger than the
 * bucket is allowed once the bucket is full, so it can never starve. */
static int
vmux_hub_take(struct vmux *vmux, size_t bytes)
{
    int ok = 0;

    pthread_mutex_lock(&vmux->state_lock);
    vmux_update_window(vmux, vmux_now(vmux));

    const uint64_t depth = vmux->rate / 10; /* 100ms of rate: the bucket size */
    const uint64_t need = (bytes > depth) ? depth : bytes;

    if (vmux->rate && vmux->window >= need) {
        vmux->window -= need;
        ok = 1;
    }
    pthread_mutex_unlock(&vmux->state_lock);
    return ok;
}

/* Returns 1 if queued, 0 if dropped (queue full / packet too large). */
static int
vmux_hub_q_push(struct vmux_hub_peer *hp, struct vmux *pm,
               const unsigned char *pkt, size_t len)
{
    if (len > VMUX_HUB_QSLOT)
        return 0;

    pthread_mutex_lock(&hp->q_lock);

    if (!hp->q) {
        hp->q = calloc(1, sizeof(*hp->q));
        if (!hp->q) {
            pthread_mutex_unlock(&hp->q_lock);
            return 0;
        }
    }
    struct vmux_hub_q *q = hp->q;
    size_t max_bytes = (size_t)(VMUX_ALOAD(&pm->rate) / 8);

    if (max_bytes < VMUX_HUB_QMIN_BYTES)
        max_bytes = VMUX_HUB_QMIN_BYTES;

    if (q->count >= VMUX_HUB_QLEN || q->bytes + len > max_bytes) {
        pthread_mutex_unlock(&hp->q_lock);
        return 0;
    }
    const unsigned int at = (q->head + q->count) % VMUX_HUB_QLEN;

    memcpy(q->data[at], pkt, len);
    q->len[at] = (uint16_t)len;
    q->count++;
    q->bytes += len;
    VMUX_ASTORE(&hp->q_count, q->count);
    pthread_mutex_unlock(&hp->q_lock);
    vmux_hub_mark(hp->hub, hp, VMUX_HUB_DIRTY_Q);
    return 1;
}

/* Encrypts one inner packet into the next TX slot. */
static int
vmux_hub_tx_add(struct vmux *pm, struct vmux_worker_scratch *sc, uint16_t *key,
               unsigned int *n, const unsigned char *plain, size_t len)
{
    struct vmux_tx_slot *s = &sc->tx[*n];
    const size_t size = vmux_encrypt(pm, vmux_now(pm), s->packet,
                                    sizeof(s->packet), plain, len);

    if (!size)
        return 0;

    memcpy(&key[*n], &s->packet[size - sizeof(key[0])], sizeof(key[0]));
    s->size = size;
    s->path = NULL;
    s->owner = pm;
    s->prepaid = 1; /* vmux_hub_take() already charged the window */
    (*n)++;
    return 1;
}

/* Selects a path for every slot (one short lock per slot, on that slot's own
 * session) and sends the batch. */
static void
vmux_hub_tx_flush(struct vmux_worker_scratch *sc, const uint16_t *key,
                 unsigned int n)
{
    const uint64_t now = vmux_now(sc->tx[0].owner);

    for (unsigned int t = 0; t < n; t++) {
        struct vmux_tx_slot *s = &sc->tx[t];
        struct vmux *pm = s->owner;

        pthread_mutex_lock(&pm->state_lock);

        struct vmux_path *path = vmux_select_path(pm, key[t]);

        if (path) {
            path->idle = now;
            s->local = path->conf.local;
            s->remote = path->conf.remote;
            s->local_ifindex = path->conf.local_ifindex;
            s->sock = path->conf.sock;
            s->path = path;
        }
        pthread_mutex_unlock(&pm->state_lock);
    }
    vmux_send_batch(sc->tx[0].owner, sc->tx, n, now);
}

/* Releases queued packets for every client that has tokens again. Cheap when
 * nothing is queued (one atomic read per client). A client another worker is
 * already draining is skipped. */
static void
vmux_hub_drain(struct vmux_hub *hub, struct vmux_worker_scratch *sc,
              unsigned char *buf)
{
    unsigned int cur = 0;
    struct vmux_hub_peer *hp;

    while ((hp = vmux_hub_dirty_next(hub, VMUX_HUB_DIRTY_Q, &cur))) {
        if (!vmux_hub_unmark(hub, hp, VMUX_HUB_DIRTY_Q))
            continue;

        if (!VMUX_ALOAD(&hp->active) || !VMUX_ALOAD(&hp->q_count))
            continue;

        if (pthread_mutex_trylock(&hp->q_lock)) {
            vmux_hub_mark(hub, hp, VMUX_HUB_DIRTY_Q);
            continue;
        }

        struct vmux *pm = __atomic_load_n(&hp->vmux, __ATOMIC_ACQUIRE);
        struct vmux_hub_q *q = hp->q;
        unsigned int tx_n = 0;
        uint16_t key[VMUX_TX_BATCH_MAX];
        const unsigned int tx_limit =
            vmux_tx_limit(VMUX_ALOAD(&hub->defaults.tx_batch));

        if (q && q->count) {
            while (q->count && tx_n < tx_limit) {
                const size_t len = q->len[q->head];

                if (!vmux_hub_take(pm, len + VMUX_PKT_MIN_SIZE))
                    break;

                memcpy(buf, q->data[q->head], len);
                q->head = (q->head + 1) % VMUX_HUB_QLEN;
                q->count--;
                q->bytes -= len;
                vmux_hub_tx_add(pm, sc, key, &tx_n, buf, len);
            }
        }
        VMUX_ASTORE(&hp->q_count, q ? q->count : 0);
        pthread_mutex_unlock(&hp->q_lock);

        if (VMUX_ALOAD(&hp->q_count))
            vmux_hub_mark(hub, hp, VMUX_HUB_DIRTY_Q);

        if (tx_n)
            vmux_hub_tx_flush(sc, key, tx_n);
    }
}

/* Ingress policing of one client's `rx` limit.
 *
 * A passive session never sends the beats that would carry a rate to the
 * client, so unlike `tx` (which the server shapes itself) an `rx` limit can
 * only be advertised -- a client that pins its own rate, or simply ignores
 * it, would send as fast as it likes. A server that serves several clients
 * has to enforce it: data over the budget is dropped, so a TCP flow backs
 * off, and counted. The bucket is 200ms deep so ordinary bursts pass. A
 * no-op unless the limit was set. */
static int
vmux_hub_rx_allow(struct vmux_hub_peer *hp, struct vmux *pm, size_t bytes)
{
    if (!(VMUX_ALOAD(&pm->policy.set) & VMUX_POLICY_RX_RATE))
        return 1;

    const uint64_t rate = VMUX_ALOAD(&pm->policy.rx_max_rate);
    const uint64_t depth = rate / 5;
    int ok = 0;

    pthread_mutex_lock(&hp->rx_lock);

    const uint64_t now = vmux_now(pm);
    uint64_t elapsed = hp->rx_time ? VMUX_TIME_MASK(now - hp->rx_time) : VMUX_ONE_SEC;

    if (elapsed >= VMUX_TIME_HALF)
        elapsed = 0; /* a clock reading older than the last refill */
    if (elapsed > VMUX_ONE_SEC)
        elapsed = VMUX_ONE_SEC;

    if (elapsed) {
        hp->rx_tokens += rate * elapsed / VMUX_ONE_SEC;
        hp->rx_time = now;
    }
    if (hp->rx_tokens > depth)
        hp->rx_tokens = depth;

    const uint64_t need = (bytes > depth) ? depth : bytes;

    if (hp->rx_tokens >= need) {
        hp->rx_tokens -= need;
        ok = 1;
    }
    pthread_mutex_unlock(&hp->rx_lock);
    return ok;
}

/* The hub counterpart of vmux_worker_loop(): same structure, same batching,
 * same locking discipline (no lock is ever held across a syscall or an AEAD
 * call), but every packet is first attributed to a peer -- on TX by routing
 * its inner destination, on RX by identifying its sender -- and then handled
 * entirely inside that peer's own session. */
int
vmux_hub_worker_loop(struct vmux_hub *hub, unsigned int worker_index,
                    unsigned int worker_count,
                    const int *tun_fds, unsigned int tun_fd_count,
                    vmux_tun_read_fn tun_read, vmux_tun_write_fn tun_write,
                    vmux_hub_oversize_fn oversize,
                    const volatile sig_atomic_t *quit)
{
    if (!hub || !tun_fds || !tun_fd_count || !tun_read || !tun_write ||
        !quit || !worker_count || worker_index >= worker_count) {
        errno = EINVAL;
        return -1;
    }
    for (unsigned int i = 0; i < tun_fd_count; i++) {
        if (tun_fds[i] < 0) {
            errno = EINVAL;
            return -1;
        }
    }
    struct vmux_worker_scratch *scratch = malloc(sizeof(*scratch));

    if (!scratch) {
        errno = ENOMEM;
        return -1;
    }
    unsigned char plain[VMUX_MTU_HARD_MAX];
    unsigned char out[VMUX_MTU_HARD_MAX];
    int ret = 0;

    while (!*quit) {
        const unsigned int sock_count = hub->sock_count;
        struct pollfd fds[VMUX_WORKERS_EXPLICIT_MAX + VMUX_SOCK_MAX];
        unsigned int fd_sock[VMUX_WORKERS_EXPLICIT_MAX + VMUX_SOCK_MAX];
        unsigned int n = tun_fd_count;

        for (unsigned int i = 0; i < tun_fd_count; i++) {
            fds[i].fd = tun_fds[i];
            fds[i].events = POLLIN;
        }
        for (unsigned int i = worker_index; i < sock_count; i += worker_count) {
            fds[n].fd = hub->sock[i];
            fds[n].events = POLLIN;
            fd_sock[n] = i;
            n++;
        }
        const int pret = poll(fds, n, vmux_hub_poll_timeout(hub, 100));

        if (pret == -1) {
            if (errno == EINTR)
                continue;
            ret = -1;
            break;
        }
        if (pret == 0) {
            vmux_hub_drain(hub, scratch, plain);
            vmux_hub_flush_all(hub, tun_fds[0], tun_write);
            continue;
        }
        /* ---------------- TX: TUN -> peer -> network ---------------- */
        int any_tun_ready = 0;

        for (unsigned int i = 0; i < tun_fd_count; i++)
            if (fds[i].revents & POLLIN)
                any_tun_ready = 1;

        if (any_tun_ready) {
            for (unsigned int off = 0; off < tun_fd_count; off++) {
                const unsigned int qi = (worker_index + off) % tun_fd_count;

                if (!(fds[qi].revents & POLLIN))
                    continue;

                const int tun_fd = tun_fds[qi];
                unsigned int tx_n = 0, tx_attempts = 0;
                uint16_t tx_key[VMUX_TX_BATCH_MAX];
                const unsigned int tx_limit =
                    vmux_tx_limit(VMUX_ALOAD(&hub->defaults.tx_batch));

                while (tx_n < tx_limit && tx_attempts < tx_limit) {
                    tx_attempts++;

                    const int r = tun_read(tun_fd, plain, sizeof(plain));

                    if (r <= 0)
                        break;

                    struct vmux_hub_peer *hp =
                        vmux_hub_route(hub, plain, (size_t)r);

                    if (!hp) {
                        VMUX_AINC(&hub->tx_drop_noroute);
                        continue;
                    }
                    struct vmux *pm = __atomic_load_n(&hp->vmux, __ATOMIC_ACQUIRE);
                    const size_t pmtu = VMUX_ALOAD(&hp->tx_mtu);

                    /* This peer's paths cannot carry a packet this large.
                     * Tell the sender (path-MTU discovery) instead of
                     * lowering the tunnel MTU for every other client. */
                    if (pmtu && (size_t)r > pmtu) {
                        VMUX_AINC(&hp->tx_drop_mtu);
                        if (oversize)
                            oversize(tun_fds[0], plain, (size_t)r, pmtu);
                        continue;
                    }
                    /* Over this client's budget, or others are already
                     * waiting ahead of this packet (order is kept): shape it
                     * rather than send it, and never stall the TUN for the
                     * other clients. */
                    if (VMUX_ALOAD(&hp->q_count) ||
                        !vmux_hub_take(pm, (size_t)r + VMUX_PKT_MIN_SIZE)) {
                        if (!vmux_hub_q_push(hp, pm, plain, (size_t)r))
                            VMUX_AINC(&hp->tx_drop_rate);
                        continue;
                    }
                    vmux_hub_tx_add(pm, scratch, tx_key, &tx_n, plain,
                                   (size_t)r);
                }
                if (tx_n)
                    vmux_hub_tx_flush(scratch, tx_key, tx_n);
            }
        }
        /* ---------------- RX: network -> peer -> TUN ---------------- */
        for (unsigned int k = tun_fd_count; k < n; k++) {
            if (fds[k].revents & POLLERR) {
                int err = 0;
                socklen_t errlen = sizeof(err);

                getsockopt(fds[k].fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
            }
            if (!(fds[k].revents & POLLIN))
                continue;

            const unsigned int sock_index = fd_sock[k];
            const int rx_n = vmux_recv_batch(fds[k].fd, scratch->rx,
                                            VMUX_BATCH_MAX);
            if (rx_n <= 0)
                continue;

            for (int j = 0; j < rx_n; j++) {
                struct vmux_rx_slot *rs = &scratch->rx[j];

                if ((rs->msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
                    rs->len <= (ssize_t)VMUX_PKT_MIN_SIZE)
                    continue;

                vmux_unmapv4(&rs->remote);

                const uint64_t sent_time = vmux_load(rs->packet, VMUX_TIME_SIZE);
                const int ctl = VMUX_MSG(sent_time) ? 1 : 0;
                const uint64_t h = vmux_hub_src_hash(&rs->remote);
                struct vmux_hub_peer *hp = vmux_hub_cache_get(hub, h);

                /* a control message ends with a client identifier */
                if (ctl && (size_t)rs->len < VMUX_PKT_MIN_SIZE + VMUX_ID_SIZE)
                    continue;

                /* A cached source still has to prove it is that peer: a
                 * control message is cheap to verify, and a mismatch means
                 * the address now belongs to someone else (a re-used NAT
                 * port, a roamed client). */
                if (hp && ctl &&
                    !vmux_decrypt_msg(__atomic_load_n(&hp->vmux, __ATOMIC_ACQUIRE),
                                     out, sizeof(out), rs->packet,
                                     (size_t)rs->len - VMUX_ID_SIZE))
                    hp = NULL;

                if (!hp) {
                    if (!ctl) {
                        VMUX_AINC(&hub->rx_drop_unknown);
                        continue;
                    }
                    hp = vmux_hub_identify(hub, rs->packet, (size_t)rs->len,
                                          out, sizeof(out));
                    if (!hp) {
                        VMUX_AINC(&hub->rx_drop_unknown);
                        continue;
                    }
                    vmux_hub_cache_put(hub, h, hp->index);
                }
                struct vmux *pm = __atomic_load_n(&hp->vmux, __ATOMIC_ACQUIRE);
                uint64_t path_hold;
                int stamped;
                uint32_t seq = 0;
                const int wn = vmux_recv_finish(pm, sock_index, &rs->msg,
                                               &rs->remote, rs->packet,
                                               rs->len, out, sizeof(out),
                                               &path_hold, &stamped, &seq);
                if (wn <= 0)
                    continue;

                const int src_ok = vmux_hub_src_ok(hp, out, (size_t)wn);

                if (src_ok <= 0) {
                    if (!src_ok)
                        VMUX_AINC(&hp->rx_drop_spoof);
                    continue;
                }
                if (!vmux_hub_rx_allow(hp, pm, (size_t)rs->len)) {
                    VMUX_AINC(&hp->rx_drop_rate);
                    continue;
                }
                int buffered = 0;

                if (VMUX_ALOAD(&pm->conf.reorder_window))
                    buffered = stamped
                        ? vmux_seq_insert(pm, seq, path_hold, vmux_now(pm),
                                         out, (size_t)wn)
                        : vmux_reorder_insert(pm, path_hold, vmux_now(pm),
                                             out, (size_t)wn);

                if (buffered)
                    vmux_hub_mark(hub, hp, VMUX_HUB_DIRTY_REORDER);
                else
                    tun_write(tun_fds[0], out, (size_t)wn);
            }
        }
        vmux_hub_drain(hub, scratch, plain);
        vmux_hub_flush_all(hub, tun_fds[0], tun_write);
    }
    free(scratch);
    return ret;
}
