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



apt-get install -y make \
                    gcc \
                    file \
                    g++ \
                    wget \
                    unzip \
                    cpio \
                    rsync \
                    bc \
                    bzip2 \
                    cmake \
                    libglib2.0-dev \
                    libsdl2-dev \
                    libpixman-1-dev \
                    nettle-dev \
                    libgtk-3-dev \
                    libjemalloc-dev \
                    libcap-ng-dev \
                    libattr1-dev \
                    libssl-dev \
                    parted

                

exit 0