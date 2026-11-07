#!/bin/sh
# 静态编译 OpenIPC/uget (C 版本) 到各目标架构, 工具链来自 toolchains.bootlin.com (musl)
# 产物默认落在本脚本同级的 build/ 目录
# 用法: sh build-uget.sh [输出目录]
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/build}
SRC=$HERE/uget.c
TC=${TC:-/home/julian/tools/toolchains}
VER=2026.08-1
mkdir -p "$OUT"

# 体积相关的公共编译/链接参数
CFLAGS="-Os -ffunction-sections -fdata-sections -fno-unwind-tables \
-fno-asynchronous-unwind-tables -fno-ident -fmerge-all-constants \
-fno-stack-protector -D_FORTIFY_SOURCE=0"
LDFLAGS="-static -no-pie -Wl,--gc-sections -Wl,--build-id=none \
-Wl,-z,noseparate-code -Wl,--hash-style=sysv -Wl,--exclude-libs,ALL"

build() {
  name=$1; arch=$2; tuple=$3
  d="$TC/$arch--musl--stable-$VER"
  cc="$d/bin/$tuple-gcc"
  strip="$d/bin/$tuple-strip"
  [ -x "$cc" ] || { echo "[missing] $name : $cc"; return 0; }
  $cc $CFLAGS $LDFLAGS -o "$OUT/$name" "$SRC"
  $strip -s -R .comment -R .note -R .note.ABI-tag -R .note.gnu.build-id \
      -R .eh_frame -R .eh_frame_hdr -R .ARM.attributes -R .jcr \
      "$OUT/$name" 2>/dev/null || $strip -s "$OUT/$name"
  printf '%-20s %8s bytes  %s\n' "$name" "$(stat -c%s "$OUT/$name")" "$(file -b "$OUT/$name" | cut -c1-70)"
}

# bootlin 只提供 armebv7-eabihf, 没有 BE 软浮点 musl。
# 这里用它的 gcc 配一份自编译的 soft-float musl (musl-1.2.5,
# -march=armv5te -mfloat-abi=soft -Os; 重建见 build-musl-armeb-sf.sh), 得到真正的 arm32be-sf。
MUSL_SF=${MUSL_SF:-$TC/musl-armeb-sf}
build_arm32be_sf() {
  d="$TC/armebv7-eabihf--musl--stable-$VER"
  tuple=armeb-buildroot-linux-musleabihf
  cc="$d/bin/$tuple-gcc"; strip="$d/bin/$tuple-strip"
  [ -x "$cc" ] || { echo "[missing] uget-arm32be-sf : $cc"; return 0; }
  [ -f "$MUSL_SF/usr/lib/libc.a" ] || { echo "[missing] uget-arm32be-sf : $MUSL_SF/usr/lib/libc.a"; return 0; }
  # --no-warn-mismatch 只为放过工具链里 hard-float 的 crtbegin/crtend/libgcc
  # (这几份都是纯整数代码, 不影响软浮点 ABI)
  $cc --sysroot="$MUSL_SF" -march=armv5te -mtune=arm926ej-s -mfloat-abi=soft \
      $CFLAGS $LDFLAGS -Wl,--no-warn-mismatch -o "$OUT/uget-arm32be-sf" "$SRC"
  $strip -s -R .comment -R .note -R .note.ABI-tag -R .note.gnu.build-id \
      -R .eh_frame -R .eh_frame_hdr -R .ARM.attributes -R .jcr \
      "$OUT/uget-arm32be-sf" 2>/dev/null || $strip -s "$OUT/uget-arm32be-sf"
  printf '%-20s %8s bytes  %s\n' "uget-arm32be-sf" "$(stat -c%s "$OUT/uget-arm32be-sf")" "$(file -b "$OUT/uget-arm32be-sf" | cut -c1-70)"
}

build uget-arm32le     armv7-eabihf    arm-buildroot-linux-musleabihf
build uget-arm32le-sf  armv5-eabi      arm-buildroot-linux-musleabi
build uget-arm32be     armebv7-eabihf  armeb-buildroot-linux-musleabihf
build_arm32be_sf
build uget-arm64le     aarch64         aarch64-buildroot-linux-musl
build uget-arm64be     aarch64be       aarch64_be-buildroot-linux-musl
build uget-mips32      mips32          mips-buildroot-linux-musl
build uget-mips32el    mips32el        mipsel-buildroot-linux-musl

# 可选: 打包一份 upx 压缩版到 $OUT/upx/，明文产物保持原样
# 上游 Makefile 就是 strip 后 `-upx $@`（连字符表示失败可忽略），这里同样不做强制
# 只压缩实测可用的架构: arm32be 的 upx 桩会 SIGILL, aarch64be 不被支持
UPX_ARCHS="arm32le arm32le-sf arm32be-sf arm64le mips32 mips32el"
UPX=${UPX:-$(command -v upx 2>/dev/null || echo /home/julian/tools/toolchains/upx/upx)}
if [ -x "$UPX" ]; then
  mkdir -p "$OUT/upx"
  rm -f "$OUT"/upx/uget-*
  for a in $UPX_ARCHS; do
    f="$OUT/uget-$a"; n="uget-$a"
    [ -f "$f" ] || continue
    cp -f "$f" "$OUT/upx/$n"
    if $UPX -9 -q "$OUT/upx/$n" >/dev/null 2>&1; then
      printf '  [upx] %-18s %7s -> %7s B\n' "$n" "$(stat -c%s "$f")" "$(stat -c%s "$OUT/upx/$n")"
    else
      rm -f "$OUT/upx/$n"
      printf '  [upx] %-18s 压缩失败, 保留明文版\n' "$n"
    fi
  done
fi
echo BUILD_DONE
