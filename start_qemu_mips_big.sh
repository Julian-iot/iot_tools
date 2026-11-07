sudo apt install -y bridge-utils uml-utilities
# 2. 创建一个名为 br0 的虚拟网桥
sudo brctl addbr br0
# 3. 给网桥 br0 分配IP地址，并启动它
sudo ifconfig br0 192.168.88.1/24 up
# 4. 创建一个名为 tap0 的虚拟网络接口
sudo tunctl -t tap0
# 5. 启动 tap0 接口，但不要给它IP (这是关键)
sudo ifconfig tap0 0.0.0.0 up
# 6. 将 tap0 接口“插”到 br0 网桥上
sudo brctl addif br0 tap0
sleep 1 
# 7. 启动 QEMU 虚拟机
sudo qemu-system-mips \
  -M malta \
  -m 256 \
  -kernel $HOME/iot_tools/kernel/vmlinux_mips32r2_eb \
  -drive file=rootfs.img,format=raw,if=ide \
  -append "root=/dev/sda rw rootfstype=ext2 init=/bin/sh console=ttyS0 loglevel=8" \
  -nographic \
  -display none \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device pcnet,netdev=net0
