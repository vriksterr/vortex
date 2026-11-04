ACLOCAL_AMFLAGS = -I m4 --install

bin_PROGRAMS = vortex

vortex_CFLAGS = $(libsodium_CFLAGS)
vortex_LDADD = $(libsodium_LIBS)
vortex_SOURCES = \
    argz/argz.c \
    argz/argz.h \
    vmux/aegis256/aegis256.c \
    vmux/aegis256/aegis256.h \
    vmux/hub.inc \
    vmux/vmux.c \
    vmux/vmux.h \
    src/argz.c \
    src/argz.h \
    src/bench.c \
    src/bind.c \
    src/common.c \
    src/common.h \
    src/ctl.c \
    src/ctl.h \
    src/hub.c \
    src/hub.h \
    src/iface.c \
    src/iface.h \
    src/ip.h \
    src/keygen.c \
    src/list.c \
    src/main.c \
    src/netlink.c \
    src/netlink.h \
    src/path.c \
    src/path_manager.c \
    src/path_manager.h \
    src/peer.c \
    src/set.c \
    src/show.c \
    src/tun.c \
    src/tun.h \
    src/version.c

EXTRA_DIST = \
    LICENSE \
    Makefile \
    README.md \
    VERSION \
    autogen.sh \
    meson.build \
    vmux/LICENSE \
    vmux/README.md \
    sodium.sh \
    systemd \
    version.sh
