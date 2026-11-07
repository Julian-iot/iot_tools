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
sudo qemu-system-arm \
 -M versatilepb \
 -kernel $HOME/iot_tools/armel_vmlinuz-3.2.0-4-versatile \
 -initrd $HOME/iot_tools/initrd.img-3.2.0-4-versatile \
 -hda $HOME/iot_tools/debian_wheezy_armel_standard.qcow2 \
 -append "root=/dev/sda1" \
 -nographic \
 -display none \
 -net nic,model=smc91c111 \
 -net tap,ifname=tap0,script=no,downscript=no