# Development

Vortex is about two thousand lines of project-owned C plus the `argz` and
`vmux` submodules. It targets C99, uses libsodium, and supports three build
workflows.

## Prepare a checkout

```sh
git submodule update --init --recursive
```

Required source directories after initialization:

```text
argz/argz.c
argz/argz.h
vmux/vmux.c
vmux/vmux.h
vmux/aegis256/aegis256.c
vmux/aegis256/aegis256.h
```

## Build workflows

### Repository Makefile

The small handwritten `Makefile` compiles the binary directly. libsodium ships
with the project in `libsodium/` (an unmodified copy of a signed release; see
`libsodium/VENDORED.txt` for the version, hash and signing key). `make` builds
it on first use with `sodium.sh`, out of tree into `.sodium/<target>-build`,
and links it statically:

```sh
make              # builds libsodium once, then vortex
make distclean    # also removes .sodium (libsodium is rebuilt next time)
```

`sodium.sh` needs no network access. It can also be run by hand and accepts an
optional cross-compilation host prefix, for example:

```sh
./sodium.sh aarch64-linux-gnu-
make X=aarch64-linux-gnu-
```

To use an installed libsodium (found with pkg-config) instead of the bundled
one:

```sh
make SODIUM=system
```

To update the bundled copy, download a newer release, verify its minisign
signature with the key recorded in `libsodium/VENDORED.txt`, and replace the
directory contents.

Install with `make install`; override `PREFIX` and `DESTDIR` as needed. The
handwritten install target moves, rather than copies, the built binary into the
destination, so a subsequent local run requires rebuilding.

### Meson

```sh
meson setup build
meson compile -C build
meson test -C build
sudo meson install -C build
```

By default Meson uses a system libsodium (1.0.4 or newer, through pkg-config)
when it finds one and otherwise builds the bundled copy and links it
statically. `-Dbundled_libsodium=enabled` always uses the bundled copy;
`-Dbundled_libsodium=disabled` requires a system one. If it finds the
systemd dependency, installation also configures and installs the instance
unit, helper scripts, and networkd profiles.

There are currently no Meson test definitions, so `meson test` is only a
sanity check that the test suite is empty unless tests are added later.

### Autotools

```sh
./autogen.sh
./configure --disable-dependency-tracking
make
make check
sudo make install
```

The release workflow uses `make distcheck`. `Makefile.am` is the source of truth
for the generated Autotools makefiles.

## Version generation

`version.sh` chooses the first available value from:

1. the `VERSION` environment variable;
2. `git describe` for a matching `v*` tag;
3. the current git commit ID;
4. the `VERSION` file; or
5. `unknown`, if none of the above are available (for example, building from
   a source tarball with no `.git` directory and no `VERSION` file -- common
   for downstream packaging such as an OpenWrt feed). Set the `VERSION`
   environment variable before invoking `make`/`configure` to avoid this.

It writes the selected value to `VERSION` as well as standard output. Build
systems define `PACKAGE_VERSION` from that result. This means configuring or
building may modify an existing `VERSION` file in the working tree.

## CI and release automation

`.github/workflows/build.yml` initializes submodules, builds the bundled libsodium,
and runs `make` on Ubuntu and macOS for every push.

For `v*` tags, `.github/workflows/upload.yml` installs system libsodium, runs
the Autotools `distcheck`, and uploads the resulting source archive to the
matching GitHub release.

When changing build inputs, keep all of these lists aligned:

* the source list in the handwritten `Makefile`;
* `vortex_SOURCES` in `Makefile.am` (the Autotools build still expects a
  system libsodium; it does not use the bundled copy); and
* the `sources` array in `meson.build`.

## Validation checklist

There is no project-owned automated unit or integration test suite in this
tree. A practical change validation pass is:

```sh
git submodule update --init --recursive
make distclean
make
./vortex version
./vortex keygen
./vortex bench fallback
```

Stop the benchmark after enough samples with `Ctrl-C`. Networking changes also
need a privileged two-peer or two-namespace test that covers:

* device creation and cleanup;
* IPv4 and, when affected, IPv6 packets;
* `list`, `show`, `set`, and all `path show` views;
* key mismatch and clock-sync diagnostics;
* MTU changes; and
* path failover/rate configuration for multipath changes.

Run at least the Make and Meson builds when editing source lists or compiler
configuration. Run `make distcheck` when changing packaging or release files.

## Adding a CLI command

1. Implement `int vx_NAME(int argc, char **argv, void *data)` in a new or
   existing source file.
2. Declare and register it in the command table in `src/main.c`.
3. Add any new source file to all three build definitions.
4. Reuse the bundled `argz` parser and the helpers in `src/argz.c` for values
   and output consistency.
5. Document the command in `docs/cli-reference.md` and add validation coverage.

## Extending the control protocol

Control requests are native `struct ctl_msg` datagrams. To add one:

1. extend `enum ctl_type` and the message union in `src/ctl.h`;
2. handle the request in the switch inside `vx_bind()`;
3. implement the client command using `ctl_reply()` or the streamed pattern
   used by path status; and
4. verify malformed, missing, and multi-reply behavior.

Keep each request and reply below the Unix datagram size limit and fully
initialize structures before sending them. Because the protocol is native and
internal, changing layouts requires the management command and daemon to come
from the same build.

## Code conventions visible in the tree

* C99 with selected GNU extensions and four-space indentation.
* Project functions and globals generally use the `vx_` prefix; subsystem
  helpers use `ctl_`, `tun_`, and `iface_`.
* Errors go to standard error through `vx_log()` or `perror()`; successful
  machine-readable/status output goes to standard output.
* System calls that can be interrupted are retried where relevant.
* Source files use short command-focused units rather than a public library
  abstraction.
