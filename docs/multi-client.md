# Multi-client servers

A normal Vortex tunnel joins two machines. **Multi-client mode** lets one
server serve many clients (up to 128) on one UDP port and one tunnel
interface. Each client is a completely separate session: it has its own key,
paths, rate limits, MTU and tunables, and nothing one client does or is
configured with can affect another.

Clients are ordinary Vortex clients. The wire protocol is unchanged, so any
existing client build works against a multi-client server.

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
* **maxpaths** caps the paths (including the monitor) a client may hold.
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

* 128 clients, 16 prefixes each. Removing a client frees its name but not its
  slot; a server that has added 128 different names must be restarted to add
  more.
* Changes made with `peer add/set/del` are not written back to the peers file.
* Clients reconnect on their own after a server restart, and a roaming client
  (new address or port) is recognised again by its key.
* Traffic from senders matching no client is dropped silently. Identifying a
  new sender is limited to 2000 attempts per second.

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
