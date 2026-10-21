#!/bin/bash
# ============================================================
# QEMU MIPS 模拟运行脚本
# - 仅定义 BASE_DIR 变量
# - 通过 TAP 网络接口与宿主机桥接
# ============================================================

BASE_DIR="$HOME/tools"
# 创建桥接网络接口
sudo brctl addbr br0
sudo ifconfig br0 192.168.88.1/24 up

# 创建 TAP 接口并加入桥接
sudo tunctl -t tap0
sudo ifconfig tap0 0.0.0.0 up
sudo brctl addif br0 tap0

sleep 1

# 启动 QEMU 模拟器
sudo qemu-system-mipsel \
  -M malta \
  -m 256 \
  -kernel "$BASE_DIR/IOT_TOOL/kernel/debian/mipsel/vmlinux-3.2.0-4-4kc-malta" \
  -hda "$BASE_DIR/IOT_TOOL/kernel/debian/mipsel/debian_wheezy_mipsel_standard.qcow2" \
  -append "root=/dev/sda1 rw console=ttyS0 loglevel=8" \
  -nographic \
  -display none \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device pcnet,netdev=net0
