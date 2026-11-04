# Getting started

This guide builds Vortex and starts one endpoint on a server and one on a
client. The examples use Linux, IPv4, UDP port 5000, and a TUN device named
`vx0`.

## Requirements

You need:

* a C99 compiler and `make` (or Meson and Ninja);
* git, including git-submodule support;
* nothing else to install: libsodium is bundled (see below);
* Linux TUN support (`/dev/net/tun`) and permission to administer network
  interfaces; and
* synchronized clocks on both peers. The protocol rejects timestamps outside
  its configured tolerance.

On Linux, tunnel operation normally requires root or `CAP_NET_ADMIN`. Building,
generating a key, printing the version, and running the crypto benchmark do not
require those privileges.

## Fetch dependencies

For a fresh clone, include the submodules:

```sh
git clone --recurse-submodules <repository-url> vortex
cd vortex
```

For an existing checkout:

```sh
git submodule update --init --recursive
```

The submodules provide the argument parser (`argz`) and encrypted multipath
transport (`vmux`). A checkout without them cannot compile.

## Build

### One command

Vortex ships with the libsodium it needs (`libsodium/`, an unmodified, signed
release). Nothing has to be installed first:

```sh
make
sudo make install        # installs one self-contained executable
```

The first `make` configures and builds libsodium privately into `.sodium/`
(about 25 seconds, no network access) and links it statically into `vortex`, so
the installed program has no libsodium dependency. Later runs reuse it.

### Using the system libsodium instead

If you prefer a distribution-provided libsodium (1.0.4 or newer, with its
development headers):

```sh
make SODIUM=system
```

### Meson

```sh
meson setup build
meson compile -C build
```

Meson uses a system libsodium when it finds one and otherwise builds the
bundled copy. Force one or the other with `-Dbundled_libsodium=enabled` or
`=disabled`.

The resulting binary is `./vortex` for Make or `./build/vortex` for Meson.
See [Development](development.md) for Autotools, cross-compiling and
installation details.

Verify the binary:

```sh
./vortex version
```

## Create the shared key

Generate one 32-byte key, encoded as 64 hexadecimal characters:

```sh
install -d -m 700 secrets
./vortex keygen > secrets/vortex.key
chmod 600 secrets/vortex.key
```

Securely copy the same key file to the other peer. Anyone with this key can
authenticate as a peer, so do not commit it, log it, or send it over an
untrusted channel.

## Start both endpoints

The CLI uses bare words rather than `--flags`. Address groups accept both an
explicit form such as `from addr 0.0.0.0 port 5000` and the compact positional
form `0.0.0.0 5000` used by the bundled scripts.

On the server at `203.0.113.10`:

```sh
sudo ./vortex bind \
  dev vx0 \
  keyfile secrets/vortex.key \
  from addr 0.0.0.0 port 5000
```

On the client:

```sh
sudo ./vortex bind \
  dev vx0 \
  keyfile secrets/vortex.key \
  from addr 0.0.0.0 port 0 \
  to addr 203.0.113.10 port 5000
```

Using local port `0` asks the operating system to select an ephemeral client
port. Omitting `dev` makes Vortex try `tun0` through `tun31`. Omitting address
options uses IPv4 wildcard address and UDP port 5000.

For IPv6, bind `::` rather than `0.0.0.0` and provide an IPv6 remote address.
Linux can receive both IPv4 and IPv6 traffic through an IPv6 wildcard socket
when the host's socket configuration permits it.

## Configure the inner network

In separate terminals, assign addresses after the TUN devices appear. For a
point-to-point example:

Server:

```sh
sudo ip address add 10.77.0.1/30 dev vx0
sudo ip link set vx0 up
```

Client:

```sh
sudo ip address add 10.77.0.2/30 dev vx0
sudo ip link set vx0 up
```

Then test from the client:

```sh
ping 10.77.0.1
```

Routing traffic beyond those two inner addresses requires additional routes,
IP forwarding, and usually firewall/NAT rules. Those choices are deployment
specific and are intentionally not performed by the `bind` command.

## Inspect and stop the tunnel

From another terminal under the same user identity as the tunnel process:

```sh
sudo ./vortex list
sudo ./vortex show dev vx0
sudo ./vortex path dev vx0
sudo ./vortex show dev vx0 errors
```

The management socket lives in a per-effective-user runtime directory. A
non-root command will therefore not discover a tunnel started as root; use
`sudo` consistently when needed.

Stop a foreground endpoint with `Ctrl-C` or send it `SIGTERM`. The TUN device is
removed on exit unless `persist` was passed to `bind`. A `SIGHUP` also stops the
process, but marks the TUN device persistent first.

## Next steps

Read [CLI reference](cli-reference.md) for path rate limits, failover settings,
clock tolerance, key rotation, and diagnostics. For managed Linux deployment,
see the systemd section in that document.
