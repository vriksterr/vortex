# Multi-client servers

A normal Vortex tunnel joins two machines. **Multi-client mode** lets one
server serve many clients (there is no fixed limit; see "Scale" below) on one UDP port and one tunnel
interface. Each client is a completely separate session: it has its own key,
paths, rate limits, MTU and tunables, and nothing one client does or is
configured with can affect another.

Clients are ordinary Vortex clients, but every build involved must carry the
client identifier described below: a client or server built before it does not
connect to one built with it.

## Finding the client (client identifier)

Every control message ends with an 8-byte client identifier: a keyed hash of the
client's pre-shared key and a 5-minute time window. The server keeps a table of
the identifiers of every client for the windows around the current time, so an
unknown source is matched to its client with one lookup, and only that client's
key is then tried (the decryption is the real check; a wrong or forged
identifier simply fails it). Data packets carry no identifier. The identifier
changes every 5 minutes, so someone watching the network cannot follow one
client across address changes by it for longer than that. A client whose clock
differs from the server's by up to the `timetolerance` (10 minutes by default)
is still found, and the existing clock check applies as before. The wire size
of control messages is unchanged: the identifier takes 8 bytes of the padding.

For the full walkthrough, with example output for every command, see the
"Serving many clients" chapter of `Notes/vortex-user-guide.html`.

## Isolation

| Per client (never shared) | Shared |
| --- | --- |
| Pre-shared key, session keys, key rotation | UDP port and sockets |
| Paths, sub-flows, health monitoring | Worker threads |
| Rate limits (both directions) and shaping queue | The TUN device |
| MTU, `pref`, loss/RTT limits, maximum paths | The routing table |
| `kxtimeout`, `timetolerance`, `keepalive`, `reorderwindow`, `strictorder` | |
| Inner addresses it may use, drop counters | |

## Quick start

```sh
# one key per client -- never share one; the server uses it to tell clients apart
vortex keygen > key-alice
vortex keygen > key-bob

# server: note there is no keyfile
vortex bind dev vx0 hub from addr 0.0.0.0 port 5000
ip addr add 10.77.0.1/24 dev vx0 && ip link set vx0 up

vortex peer add alice key key-alice allowed 10.77.0.2/32 rate tx 30mbit rx 30mbit
vortex peer add bob   key key-bob   allowed 10.77.0.3/32 rate tx 80mbit rx 80mbit

# each client, exactly as for a normal tunnel, with its own key
vortex bind dev vx0 keyfile key-alice from addr 0.0.0.0 port 0 to addr SERVER port 5000
```

Clients can instead be listed in a peers file, one per line, using the words
that follow `peer add`:

```text
alice key /etc/vortex/key-alice allowed 10.77.0.2/32 rate tx 30mbit rx 30mbit
bob   key /etc/vortex/key-bob   allowed 10.77.0.3/32 mtu 1400
```

```sh
vortex bind dev vx0 peers /etc/vortex/peers.conf from addr 0.0.0.0 port 5000
```

## `bind` options

* `hub` -- run as a multi-client server. `keyfile` is not allowed; each client
  has its own.
* `peers FILE` -- load clients at start-up (implies `hub`). A file with an
  error is rejected as a whole, naming the line.
* `mtu N` -- pin the tunnel MTU (576-65535). Without it the MTU follows the
  largest client.

## `peer` command

```text
vortex peer add  NAME key FILE allowed ADDR/LEN[,ADDR/LEN...] [OPTIONS]
vortex peer set  NAME [allowed ...] [OPTIONS] [unset SETTING[,SETTING...]]
vortex peer del  NAME
vortex peer list
vortex peer show NAME
```

Options: `rate tx RATE rx RATE`, `mtu N`, `pref N`, `losslimit PERCENT`,
`rttlimit DURATION`, `maxpaths N`, `kxtimeout`, `timetolerance`, `keepalive`,
`reorderwindow`, `strictorder on|off`, and `dev NAME` to select the tunnel.

* **allowed** lists the inner prefixes a client owns (up to 16, IPv4 and
  IPv6). The destination of every packet leaving the server selects the client
  (longest prefix), and the source of every packet a client sends must be one
  of them, otherwise it is dropped and counted as `spoofed`. A prefix, a key
  and a name can each belong to only one client.
* **rate tx** is enforced by shaping: packets over the limit wait in a short
  per-client queue (about 125 ms of the rate) and are dropped only if it
  fills.
* **rate rx** is enforced by policing on arrival (200 ms burst): the server
  cannot tell a client to slow down in advance, so traffic over the limit is
  dropped.
* **mtu, pref, losslimit, rttlimit** replace what the client advertises.
* **maxpaths** caps the paths (including the monitor) a client may hold. There is
  no cap unless this is set. Set it at least as high as the number of paths the
  client really uses (its ISPs times their `connections`, plus one monitor per
  ISP): a client that tries to use more than the cap has the extra sub-flows
  ignored by the server, and its traffic suffers.
* **unset** stops enforcing a setting, so the client's own value applies again.
  A value shown as `client` in the output means "not enforced by the server".

On a multi-client tunnel `path`, `show errors` and `set` accept `peer NAME`;
`show` reports the mode, client count and tunnel-wide drop counters;
`path up/down` is not supported (the client creates its own paths).

## MTU

The tunnel interface MTU follows the **largest** client rather than the
smallest. A packet too large for the one client it is addressed to is dropped
and answered with ICMP "fragmentation needed" (IPv4) or "packet too big"
(IPv6), so only that destination's sender shrinks its packets.

## Routing and forwarding

The server's interface needs an address in the clients' network; each client
needs one too. Internet access for clients and client-to-client traffic rely
on the operating system's forwarding (`net.ipv4.ip_forward=1`; also
`net.ipv4.conf.all.send_redirects=0`) and are not performed by Vortex.

## systemd

`vortex-hub@.service` runs
`vortex bind dev $DEV hub peers /etc/vortex/%i/peers.conf from addr $BIND port $BIND_PORT $OPTIONS`
with `/etc/vortex/%i/env` as its environment. Key files must be owned by
root (the unit keeps only `CAP_NET_ADMIN`), and an optional `post.sh` should
begin by waiting for the interface to exist.

## Limits and behaviour worth knowing

* No fixed limit on the number of clients, 16 prefixes each. The table of
  clients grows as clients are added. A removed client's memory and slot are
  released about a minute later and reused by the next client added.
* Changes made with `peer add/set/del` are not written back to the peers file.
* Clients reconnect on their own after a server restart, and a roaming client
  (new address or port) is recognised again by its key.
* Traffic from senders matching no client is dropped silently. Identifying a
  new sender is limited to 20000 attempts per second.

## Scale

The cost of a client does not grow with the number of other clients: a packet
is matched to its client by hash lookups (the inner destination address on the
way out, the client identifier for a new sender on the way in), adding or
removing a client changes only that client's table entries, and a client that
has nothing buffered or queued is not visited by the workers. Measured on a
4-core VM with 20,000 registered clients and 4 connected ones: about 13 KB of
memory per registered client that is not connected, adding a client about 3 ms
(mostly the `vortex peer add` process itself), starting from a peers file of
20,000 entries about 8 seconds, about 2% CPU for the idle clients, and no
measurable effect on the connected clients' throughput.

A connected client costs more: its own paths and buffers (reorder buffers are
allocated only once a client actually needs them), and, because every path
sends a control message about every 100 ms, receive work that grows with the
number of paths in use. This has not been measured with large numbers of
*connected* clients (the tests above had four); expect the housekeeping pass
that runs every 100 ms and visits every client that has ever had a path, and
the per-path control traffic, to become the limits long before the tables do.
Each client also takes about 1 MB of address space (only the pages it touches
are real memory).

## Many paths per client

A client can bring as many ISPs and sub-flows as it likes; the server creates a
path for each source address and port it hears from, with no fixed limit. Two
things to know:

* Every path exchanges control messages (a "beat" about every 100 ms, answered
  by the other side), so the control traffic grows with the number of paths. At
  2,000 paths in one tunnel on a 4-core VM that is enough to make the tunnel
  unusable at the default beat (about 5 Mbit/s, 80 ms latency), and perfectly
  usable at `beat 1s` on the paths (about 670 Mbit/s, 2 ms). With many paths,
  raise the beat (`path up ... beat 1s`).
* Each sub-flow is a socket on the client, so the client process needs an open
  files limit above its sub-flow count (`ulimit -n`, or `LimitNOFILE=` in a
  systemd unit). One tunnel is also limited to 4,096 sub-flow sockets
  (`VMUX_SOCK_MAX`).

`vortex path` lists at most 512 paths at a time and says how many there are in
all.

## Implementation notes

* `vmux/vmux.c` keeps a single-peer session per `struct vmux`. The hub
  (`vmux/hub.inc`, included at the end of `vmux.c`) owns the shared sockets and
  holds one fully independent `struct vmux` per client, so isolation follows
  from the structure rather than from filtering.
* Receive: a datagram's source address is looked up in a lock-free cache; a
  miss is resolved only for control messages, by trying each client's key.
* Transmit: the inner destination selects the client; the client's rate window
  is charged atomically when a packet is approved (several workers share one
  window); packets over budget wait in that client's own queue.
* The server-side policy (`struct vmux_policy`) is re-applied after every
  control message a client sends, so it always wins over the client's
  advertisement.
* Each session generates its key pair when it is created, not on the first
  housekeeping tick; otherwise a control message handled at start-up could be
  answered with an all-zero public key.
