#!/bin/sh
# 生成 BE 软浮点 musl 静态库, 供 uget-arm32be-sf 链接使用
# (bootlin 只提供 armebv7-eabihf 硬浮点, 没有 BE 软浮点工具链)
# 产物: $TC/musl-armeb-sf/usr/{include,lib}
set -e
TC=${TC:-/home/julian/tools/toolchains}
PREFIX=${PREFIX:-$TC/musl-armeb-sf}
VER=1.2.5
TARBALL=${TARBALL:-/tmp/musl-$VER.tar.gz}
SRCDIR=${SRCDIR:-/tmp/musl-$VER}
GCCDIR=$TC/armebv7-eabihf--musl--stable-2026.08-1
CC=$GCCDIR/bin/armeb-buildroot-linux-musleabihf-gcc
[ -x "$CC" ] || { echo "缺少 $CC"; exit 1; }

[ -f "$TARBALL" ] || curl -fL -o "$TARBALL" https://musl.libc.org/releases/musl-$VER.tar.gz
[ -d "$SRCDIR" ] || tar -C "$(dirname "$SRCDIR")" -xzf "$TARBALL"

cd "$SRCDIR"
make distclean >/dev/null 2>&1 || true
# configure 的编译器自检会用工具链默认(硬浮点)libc, 所以这里先不带 soft 参数,
# 之后直接改 config.mak; 工具名靠 PATH 找到
PATH=$GCCDIR/bin:$PATH ./configure --prefix=/usr --disable-shared \
    --target=armeb-linux-musleabi
sed -i 's/^SUBARCH = ebhf/SUBARCH = eb/; s|^CFLAGS = $|CFLAGS = -Os -march=armv5te -mtune=arm926ej-s -mfloat-abi=soft|' config.mak
PATH=$GCCDIR/bin:$PATH make -j"$(nproc)"
rm -rf "$PREFIX"
PATH=$GCCDIR/bin:$PATH make install DESTDIR="$PREFIX"
echo "MUSL_SF_OK $PREFIX"
