#!/bin/bash
git submodule update --init --recursive

cd buildroot
git checkout 2023.08

cd ../u-boot
git checkout v2023.07
git am -3 --keep-cr --ignore-space-change ../patches/u-boot/*.patch

cd ../qemu
git checkout v6.2.0
git am -3 --keep-cr --ignore-space-change ../patches/qemu/*.patch

cd ../libspdm
git checkout dc48779a5b8c9199b01549311922e05429af2a0e
git am -3 --keep-cr --ignore-space-change ../patches/libspdm/*.patch
cd ..

. ./env.sh

gcc -Wall -o sniffer sniffer.c

make broot

make spdm

make qemu

make payload

exit 0