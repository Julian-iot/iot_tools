#!/bin/bash
dd if=/dev/zero of=rootfs.img bs=1M count=256
mkfs.ext2 rootfs.img
# 创建一个临时挂载点: 
mkdir ./temp_mount
# 用loop方式挂载镜像: 
sudo mount -o loop rootfs.img ./temp_mount
# 将固件文件复制进去: 
sudo cp -r ./squashfs-root/* ./temp_mount/
# 卸载镜像: 
sudo umount ./temp_mount