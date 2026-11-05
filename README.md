# Vortex

Vortex is a small, simple and secure multipath UDP tunnel.

Vortex is a fork of [glorytun](https://github.com/angt/glorytun) by Adrien
Gallouët, and its transport library, **vmux**, is derived from
[mud](https://github.com/angt/mud) by the same author. Both are used under their
original BSD-3-Clause licence (see `LICENSE` and `vmux/LICENSE`). The upstream
project's stable branch and wiki are at the glorytun link above.

## Documentation

* [User guide](docs/user-guide.html) -- a complete walk-through, from
  concepts and install to every command, multi-client servers and tuning
  (open the file in a browser).
* [Getting started](docs/getting-started.md), [CLI reference](docs/cli-reference.md),
  [Multi-client servers](docs/multi-client.md), [Architecture](docs/architecture.md)
  and [Development](docs/development.md).

## Features

The key features of Vortex come directly from vmux (derived from
[mud](https://github.com/angt/mud)).

 * **Fast and highly secure**

   When AES-NI is available, the new and extremely fast AEAD construction
   [AEGIS-256](https://github.com/angt/aegis256) is used.
   Otherwise, an automatic fallback to ChaCha20-Poly1305 is done in both peers.
   All messages are encrypted, authenticated and timestamped to mitigate a
   large set of attacks.
   This implies that the client and the server must be synchronized,
   an offset of 10min is accepted by default.
   Perfect forward secrecy is also implemented with ECDH over Curve25519.
   Keys are rotated every hours.

 * **Multipath and failover**

   Connectivity is now crucial, especially in the SD-WAN world.
   This feature allows a TCP connection (and all other protocols) to explore
   and exploit all available links without being disconnected.
   Aggregation should work on all conventional links.
   Only very high latency (+500ms) links are not recommended for now.
   Backup paths are also supported, they will be used only in case of emergency,
   it is useful when aggregation is not your priority.

 * **Traffic shaping**

   Shaping is very important in network, it allows to keep a low latency
   without sacrificing the bandwidth.
   It also helps the multipath scheduler to make better decisions.
   Currently it must be configured by hand, but soon Vortex will do it
   for you.

 * **Fixed, operator-set MTU**

   Bad MTU configuration is a very common problem in the world of VPN.
   Each path sends at a single fixed wire size (`path up ... mtu N`,
   default 1400) rather than probing for it -- no ICMP next-hop MTU
   dependency, and nothing to black-hole. Set on one end, the value is
   advertised to the peer and adopted there automatically unless it has its
   own explicit value configured too. In asymmetric situations the tunnel's
   effective MTU is the minimum of every path's own fixed size.

## Changes in this fork

This build carries a few changes on top of upstream vortex/vmux, beyond the
interface-rebinding patch (`vmux_rebind_path`, `via IFACE` path selection)
this fork's `vmux` submodule already added. None of them touch the wire
protocol, so they're safe to deploy on one end of a tunnel at a time.

 * **Pinned rates actually stay pinned**

   Previously, an explicitly configured `path ... rate tx X` could be
   silently overwritten within about 100ms by the peer's own advertised
   `rx` rate, every time a keepalive arrived. A path's tx rate is now
   marked pinned once set locally, and the peer can no longer reset it.

 * **Multi-core encryption and decryption**

   AEAD encrypt/decrypt now run across a worker-thread pool sized to the
   machine's CPU core count instead of a single core doing all the crypto
   work. Path selection, rate limiting, and the actual socket I/O stay
   single-threaded, since those hold shared tunnel state that isn't safe
   to parallelize without a much larger rewrite.

   This does not scale to very high core counts. The pool is capped at
   8 worker threads (`VMUX_WORKERS_MAX` in `vmux/vmux.c`) regardless of how
   many cores are available, and even without that cap, throughput would
   plateau well before it: every worker pulls jobs from a single
   mutex-protected queue, and the packet-read/path-selection/socket-I/O
   work described above is single-threaded no matter the core count.
   Expect this to help meaningfully on machines with roughly 2-8 cores;
   a 64- or 128-core box will not see proportional gains from it alone.

 * **Batched packet I/O**

   The main event loop drains up to 256 packets per direction per wakeup
   instead of one, cutting `select()`/syscall overhead per packet at high
   throughput. The tx-rate limiter is still enforced exactly as before,
   just decided per batch instead of per packet.

 * **Configurable RTT-based path health (`rttlimit`)**

   A new `path ... set rttlimit DURATION` option, mirroring the existing
   `losslimit`: once a path's measured RTT exceeds the configured limit
   it's marked `late` and excluded from the active bond, automatically
   rejoining once RTT recovers.

 * **Richer default `path` status output**

   `vortex path` with no arguments now also prints RTT, TX-LOSS, and
   RX-LOSS alongside STATUS/PUBLIC, instead of requiring a separate
   `show rtt` or `show stat` call.

 * **Optional packet resequencing (`reorderwindow`)**

   Multipath striping schedules per packet, not per flow, so a single
   TCP-like flow crossing several paths at once routinely sees packets
   arrive out of order and throttles itself as if they'd been lost. `set
   ... reorderwindow DURATION` (off by default) turns it on: the receiver
   puts packets back in the order they were sent before handing them to
   TCP. `strictorder on|off` (on by default) chooses exact sequence numbers,
   TCP included, over the older round-trip-time estimate; `reorderwindow` is
   then only the longest wait for a missing packet. Set both on both ends.
   See `docs/cli-reference.md` and "Packet resequencing" in
   `docs/architecture.md`.

 * **Adjustable send bursts (`txbatch`)**

   Each worker reads up to 16 packets from the tunnel device and sends them
   back to back. `set ... txbatch N` (1-128, default 16) changes that; a
   smaller value gives shorter bursts, which can mean fewer drops on a link
   with a shallow buffer, at the cost of more CPU. It only affects what this
   end sends and takes effect at once. See `docs/cli-reference.md`.

## Multi-client servers

One server can serve many clients on a single port, each with its own key, rate
limits, MTU and tunables, fully isolated from the others (`bind ... hub`,
`peer add`, ...). Existing clients work unchanged. See
[docs/multi-client.md](docs/multi-client.md).

## Compatibility

Vortex needs [libsodium](https://github.com/jedisct1/libsodium), and ships with it:
an unmodified copy of libsodium 1.0.22 (ISC licence) is in `libsodium/`, so
`make` builds everything and the installed program is a single self-contained
executable. A system libsodium (>= 1.0.4) can be used instead with
`make SODIUM=system`.

Linux is the platform of choice but the code is standard so it should be
easily ported on other posix systems.
It was successfully tested on OpenBSD, FreeBSD and MacOS.

IPv4 and IPv6 are supported.
On Linux you can have both at the same time by binding `::`.

---
For feature requests and bug reports about this fork, please use the issue
tracker of the repository you obtained it from. Issues in the original projects
belong to [glorytun](https://github.com/angt/glorytun/issues) and
[mud](https://github.com/angt/mud/issues).
