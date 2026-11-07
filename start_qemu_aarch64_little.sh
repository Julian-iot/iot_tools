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
sudo qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a57 \
  -kernel $HOME/tools/iot_tools/kernel/Image_aarch64v8_el_4k \
  -drive file=rootfs.img,format=raw,if=virtio \
  -append "root=/dev/vda rw rootfstype=ext2 init=/bin/sh console=ttyAMA0 loglevel=8" \
  -nographic \
  -netdev tap,id=mynet,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=mynet
