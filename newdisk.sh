#!/bin/bash

dd if=/dev/zero of=disk.img bs=1M count=128
parted disk.img mklabel gpt

i=$(losetup --find --show disk.img)


parted --align minimal ${i} mkpart primary ext4 0% 50%
parted --align minimal ${i} mkpart primary ext4 50% 100%
mkfs.ext4 ${i}p1
mkfs.ext4 ${i}p2
parted ${i} set 1 boot on
mkdir /mnt/boot
mkdir /mnt/rootfs
mkdir /mnt/buildroot
j=$(sudo losetup --find --show /home/duvanel/git/riscv-spdm/buildroot/output/images/rootfs.ext2)


mount ${j} /mnt/buildroot
mount ${i}p1 /mnt/boot
mount ${i}p2 /mnt/rootfs
cp /home/duvanel/git/riscv-spdm/buildroot/output/images/Image /mnt/boot
cp /mnt/buildroot/* /mnt/rootfs


umount /mnt/boot
umount /mnt/rootfs
umount /mnt/buildroot
losetup -d ${i}
losetup -d ${j}
rm -rf /mnt/*