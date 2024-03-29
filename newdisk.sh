#!/bin/bash

export WORKSPACE=$(pwd)

dd if=/dev/zero of=disk.img bs=1M count=128
sudo parted disk.img mklabel gpt

i=$(sudo losetup --find --show disk.img)

sudo parted --align minimal ${i} mkpart primary ext4 0% 50%
sudo parted --align minimal ${i} mkpart primary ext4 50% 100%
sudo mkfs.ext4 ${i}p1
sudo mkfs.ext4 ${i}p2
sudo parted ${i} set 1 boot on
sudo mkdir /mnt/boot
sudo mkdir /mnt/rootfs
sudo mkdir /mnt/buildroot

j=$(sudo losetup --find --show ${WORKSPACE}/buildroot/output/images/rootfs.ext2)

sudo mount ${j} /mnt/buildroot
sudo mount ${i}p1 /mnt/boot
sudo mount ${i}p2 /mnt/rootfs
sudo cp -r ${WORKSPACE}/buildroot/output/images/Image /mnt/boot
sudo cp -r /mnt/buildroot/* /mnt/rootfs


sudo umount /mnt/boot
sudo umount /mnt/rootfs
sudo umount /mnt/buildroot
sudo losetup -d ${i}
sudo losetup -d ${j}
sudo rm -rf /mnt/*