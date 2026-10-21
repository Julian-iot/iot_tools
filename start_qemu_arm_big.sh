#!/bin/bash
# ----------------------------------------------------------------------
# QEMU 启动脚本：TAP 网络设置、运行 QEMU 和清理
# ----------------------------------------------------------------------
BASE_DIR="$HOME/tools"
# QEMU 启动参数：
QEMU_CMD=(
    sudo qemu-system-arm 
    -M vexpress-a9
    -m 512M
    -no-user-config
    -kernel $BASE_DIR/IOT_TOOL/kernel/zImage_arm_big
    -dtb $BASE_DIR/IOT_TOOL/kernel/zImage_arm_big-vexpress-v2p-ca9.dtb
    -nographic
    -append "root=/dev/mmcblk0 rw rootfstype=ext2 init=/bin/sh console=ttyAMA0 loglevel=8"
    -drive file=rootfs.img,format=raw,if=sd
    -netdev tap,id=net0,ifname=tap0,script=no,downscript=no
    -device virtio-net-device,netdev=net0
)

# 清理函数：拆除网络接口并重置终端
cleanup() {
    echo "--- 清理网络接口 (tap0, br0) ---"
    # 尝试关闭接口并移除桥接
    if sudo ifconfig tap0 down 2>/dev/null; then
        sudo brctl delif br0 tap0 2>/dev/null
    fi
    if sudo ifconfig br0 down 2>/dev/null; then
        sudo brctl delbr br0 2>/dev/null
    fi
    # 移除 tap0 接口
    sudo tunctl -d tap0 2>/dev/null
    
    # 强制终端恢复到正常模式，防止 QEMU 退出导致的缩进错乱
    stty sane
    echo "--- 清理完成，终端已重置 ---"
}

# 确保脚本退出时执行清理
# 捕获 SIGINT (Ctrl+C), SIGTERM (kill), EXIT
trap cleanup EXIT INT TERM

echo "--- 1. 安装必要的工具 (如果未安装) ---"
sudo apt install -y bridge-utils uml-utilities

echo "--- 2. 配置 TAP/Bridge 网络 ---"
# 创建虚拟网桥
sudo brctl addbr br0
# 给网桥 br0 分配IP地址，并启动它
sudo ifconfig br0 192.168.88.1/24 up
# 创建 tap0 接口
sudo tunctl -t tap0
# 启动 tap0 接口，但不要给它IP
sudo ifconfig tap0 0.0.0.0 up
# 将 tap0 接口“插”到 br0 网桥上
sudo brctl addif br0 tap0

echo "--- 3. 启动 QEMU 虚拟机 (使用 'Ctrl+A, X' 或发送 SIGTERM/SIGINT 退出) ---"
# 给予网络配置一些时间
sleep 1 

# 执行 QEMU 命令
"${QEMU_CMD[@]}"

# QEMU 退出后，trap 机制会自动调用 cleanup 函数。
