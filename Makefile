NAME     = vortex

# libsodium
#   bundled (default): build the copy that ships in ./libsodium on first use and
#                      link it statically -- nothing needs to be installed.
#   system           : use an installed libsodium (found with pkg-config):
#                          make SODIUM=system
SODIUM   = bundled

CC       = cc
ifneq ($(X),)
# cross-compiling: toolchains ship <prefix>gcc, not <prefix>cc
CC       = gcc
endif
CFLAGS   = -std=c99 -O2 -Wall -fstack-protector-strong -pthread
ifeq ($(SODIUM),system)
CPPFLAGS = $(shell pkg-config --cflags libsodium 2>/dev/null)
LDFLAGS  = $(shell pkg-config --libs-only-L libsodium 2>/dev/null)
LDLIBS   = $(shell pkg-config --libs-only-l libsodium 2>/dev/null || echo -lsodium)
SODIUM_LIB =
else
CPPFLAGS = -I.sodium/$(X)build/src/libsodium/include
LDFLAGS  = -L.sodium/$(X)build/src/libsodium/.libs
LDLIBS   = -lsodium
SODIUM_LIB = .sodium/$(X)build/src/libsodium/.libs/libsodium.a
endif
prefix   = /usr/local
PREFIX   = $(prefix)

$(NAME): $(SODIUM_LIB)
	$(X)$(CC) $(EXTRA) \
	    $(CFLAGS) \
	    $(CPPFLAGS) \
	    $(LDFLAGS) \
	    -DPACKAGE_NAME=\"$(NAME)\" \
	    argz/argz.c \
	    vmux/aegis256/aegis256.c \
	    vmux/vmux.c \
	    src/argz.c \
	    src/bench.c \
	    src/bind.c \
	    src/common.c \
	    src/ctl.c \
	    src/hub.c \
	    src/iface.c \
	    src/keygen.c \
	    src/list.c \
	    src/main.c \
	    src/netlink.c \
	    src/path.c \
	    src/path_manager.c \
	    src/peer.c \
	    src/set.c \
	    src/show.c \
	    src/tun.c \
	    src/version.c \
	    -o $(NAME) \
	    $(LDLIBS)

install: $(NAME)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mv -f $(NAME) $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(NAME)

clean:
	rm -f $(NAME)

# also forget the private libsodium build (rebuilt on the next make)
distclean: clean
	rm -rf .sodium

ifneq ($(SODIUM_LIB),)
$(SODIUM_LIB):
	sh ./sodium.sh $(X)
endif

.PHONY: $(NAME) install uninstall clean distclean
