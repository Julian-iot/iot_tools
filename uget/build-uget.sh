#!/bin/sh
# 静态编译 OpenIPC/uget (C 版本) 到八个目标（mips32/arm32/arm64，大小端，arm 硬/软浮点）
# 产物落在本脚本同级的 build/（已去符号表，部署用），upx 副本在 build/upx/
# 用法: sh build-uget.sh [输出目录]
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/build}
SRC=$HERE/uget.c
TC=${TC:-/home/julian/tools/toolchains}
VER=${VER:-2026.08-1}
UPX=${UPX:-$(command -v upx 2>/dev/null || true)}
# BE 软浮点 musl（bootlin 没有这套工具链，需要用 armebv7-eabihf 的 gcc 自编一份）
MUSL_SF=${MUSL_SF:-$TC/musl-armeb-sf}
mkdir -p "$OUT"

CFLAGS="-Os -ffunction-sections -fdata-sections -fno-unwind-tables \
-fno-asynchronous-unwind-tables -fno-ident -fmerge-all-constants -fno-stack-protector"
LDFLAGS="-static -no-pie -Wl,--gc-sections -Wl,--build-id=none \
-Wl,-z,noseparate-code -Wl,--hash-style=sysv -Wl,--exclude-libs,ALL"
STRIPFLAGS="-s -R .comment -R .note -R .note.ABI-tag -R .note.gnu.build-id \
-R .eh_frame -R .eh_frame_hdr -R .ARM.attributes -R .jcr"

report() {
  name=$1; nm=$2
  printf '%-18s %7s B  符号=%s  %s\n' "$name" "$(stat -c%s "$OUT/$name")" \
    "$("$nm" "$OUT/$name" 2>/dev/null | wc -l)" \
    "$(file -b "$OUT/$name" | cut -c1-58)"
}

build() {
  name=$1; arch=$2; tuple=$3
  d="$TC/$arch--musl--stable-$VER"
  cc="$d/bin/$tuple-gcc"; strip="$d/bin/$tuple-strip"; nm="$d/bin/$tuple-nm"
  [ -x "$cc" ] || { echo "[missing] $name : $cc"; return 0; }
  $cc $CFLAGS $LDFLAGS -o "$OUT/$name" "$SRC"
  $strip $STRIPFLAGS "$OUT/$name" 2>/dev/null || $strip -s "$OUT/$name"
  report "$name" "$nm"
}

# BE 软浮点：用 armebv7-eabihf 的 gcc 配自编的 soft-float musl（MUSL_SF）
build_arm32be_sf() {
  name=uget-arm32be-sf
  d="$TC/armebv7-eabihf--musl--stable-$VER"
  tuple=armeb-buildroot-linux-musleabihf
  cc="$d/bin/$tuple-gcc"; strip="$d/bin/$tuple-strip"
  [ -x "$cc" ] || { echo "[missing] $name : $cc"; return 0; }
  [ -f "$MUSL_SF/usr/lib/libc.a" ] || { echo "[missing] $name : $MUSL_SF/usr/lib/libc.a"; return 0; }
  # --no-warn-mismatch 只为放过工具链里 hard-float 的 crtbegin/crtend/libgcc（纯整数代码）
  $cc --sysroot="$MUSL_SF" -march=armv5te -mtune=arm926ej-s -mfloat-abi=soft \
      $CFLAGS $LDFLAGS -Wl,--no-warn-mismatch -o "$OUT/$name" "$SRC"
  $strip $STRIPFLAGS "$OUT/$name" 2>/dev/null || $strip -s "$OUT/$name"
  report "$name" "$nm"
}

build uget-arm32le     armv7-eabihf    arm-buildroot-linux-musleabihf
build uget-arm32le-sf  armv5-eabi      arm-buildroot-linux-musleabi
build uget-arm32be     armebv7-eabihf  armeb-buildroot-linux-musleabihf
build_arm32be_sf
build uget-arm64le     aarch64         aarch64-buildroot-linux-musl
build uget-arm64be     aarch64be       aarch64_be-buildroot-linux-musl
build uget-mips32      mips32          mips-buildroot-linux-musl
build uget-mips32el    mips32el        mipsel-buildroot-linux-musl

# AArch64 只有小端一种编码（aarch64_be 是另一套），aarch64_el 与 aarch64-linux-musl 等价，另存一份别名
if [ -f "$OUT/uget-arm64le" ]; then
  cp -f "$OUT/uget-arm64le" "$OUT/uget-aarch64el"
  printf '%-18s %7s B  (与 uget-arm64le 同一产物)\n' uget-aarch64el "$(stat -c%s "$OUT/uget-aarch64el")"
fi

# 可选: 再打一份 upx 压缩副本到 $OUT/upx/
# 只压缩实测能跑的架构：arm32be 的 upx 桩是 BE32 而二进制是 BE8（SIGILL），aarch64be 无 stub
if [ -n "$UPX" ] && [ -x "$UPX" ]; then
  mkdir -p "$OUT/upx"
  rm -f "$OUT"/upx/uget-*
  for a in arm32le arm32le-sf arm32be-sf arm64le mips32 mips32el; do
    f="$OUT/uget-$a"; n="uget-$a"
    [ -f "$f" ] || continue
    cp -f "$f" "$OUT/upx/$n"
    if $UPX -9 -q "$OUT/upx/$n" >/dev/null 2>&1; then
      printf '  [upx] %-18s %7s -> %7s B\n' "$n" "$(stat -c%s "$f")" "$(stat -c%s "$OUT/upx/$n")"
    else
      rm -f "$OUT/upx/$n"
      printf '  [upx] %-18s 压缩失败，保留明文版\n' "$n"
    fi
  done
else
  echo "[skip] 没找到 upx，跳过压缩"
fi
echo BUILD_DONE
