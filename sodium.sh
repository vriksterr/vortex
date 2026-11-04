#!/bin/sh
#
# Builds the libsodium that ships in ./libsodium as a private static library
# in ./.sodium/<host>-build. No network access and no system libsodium needed.
#
# usage: ./sodium.sh [cross-compiler-prefix-]     e.g. ./sodium.sh aarch64-linux-gnu-
#
# The top-level Makefile runs this by itself the first time it is needed.

set -e

ROOT=$(cd "$(dirname "$0")" && pwd)

[ -f "$ROOT/libsodium/configure" ] || {
	echo "libsodium/configure is missing: the bundled libsodium source is incomplete" >&2
	exit 1
}

HOST="${1%-}"
DIR="$ROOT/.sodium/${HOST:+$HOST-}build"

mkdir -p "$DIR"
cd "$DIR"

# Out-of-tree: nothing under ./libsodium is ever modified.
"$ROOT/libsodium/configure" ${HOST:+--host=$HOST} \
	--disable-dependency-tracking \
	--enable-minimal \
	--enable-static \
	--disable-shared

NPROC=$( (sysctl -n hw.ncpu || nproc) 2>/dev/null || echo 1)
make "-j$((NPROC+1))"

# the generated version.h lives in the build tree, everything else in the source tree
mkdir -p src/libsodium/include
cp -a "$ROOT/libsodium/src/libsodium/include/." src/libsodium/include/
