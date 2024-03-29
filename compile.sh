#!/bin/bash
unset WORKSPACE NPROC BIN_DIR CC_RISCV64 SPDM_DIR SPDM_BUILD_DIR

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

export WORKSPACE=$(pwd)
export NPROC=$(nproc)
export BIN_DIR=$WORKSPACE/buildroot/output/host/bin
export CC_RISCV64=$BIN_DIR/riscv64-linux-
export SPDM_DIR=$WORKSPACE/libspdm
export SPDM_BUILD_DIR=$SPDM_DIR/build_uboot
export PATH="$PATH:$WORKSPACE/buildroot/output/host/bin"

if [ "$(uname -m)" = "x86_64" ]
then
    export HOST_ARCH="x64"
else
    export HOST_ARCH=$(uname -m)
fi

gcc -Wall -o sniffer sniffer.c

make broot

make spdm

make qemu

make payload