# RISC-V 64 bits with LibSPDM on QEMU

This repository is a fork of an implementation of LibSPDM inside QEMU and Das U-Boot especifically for RISC-V 64 bits.
Please, access the original project and give it a star.
This is just a modification to proper run with a opened socket in VirtIO to export packets to an echo server in TCP port 2323
(spdm_sniffer.c).

Then, you can read those packets with Wireshark, using the SPDM-WID dissector.

# Compilation Steps

## Initial Configuration

First, you need some dependencies:

```bash
make 
gcc 
file 
g++ 
wget 
unzip 
cpio 
rsync 
bc 
bzip2 
cmake 
libglib2.0-dev 
libsdl2-dev 
libpixman-1-dev 
nettle-dev 
libgtk-3-dev 
libjemalloc-dev 
libcap-ng-dev 
libattr1-dev 
libssl-dev
parted
```

```bash
[th-duvanel@~/riscv-spdm]
chmod +x *.sh
. ./env.sh
./compile.sh
```
I know, it is strange to have a Makefile in the repo and you have to use a shell script. But the Git repos have to compile themselves
individually. If not, it can cause some unexpected errors, so, use the script above.

# Running

For the qemu emulation, run the .sh to create a virtual disk:
```bash
[th-duvanel@~/riscv-spdm]
./newdisk.sh
```
I'm sorry for the sudo commands inside newdisk.sh. It is because the compilation and environemnt variables aren't the same if you're running the
script with and without it. If you want it, you can run it separetely.

If you restart your computer, you need to run again the environemnt variables:

```bash
[th-duvanel@~/riscv-spdm]
. ./env.sh
```

Now, run in this order:
- (1th) The sniffer (server, echo, etc.), make sure you have the 2323 TCP port on
```bash
[th-duvanel@~/riscv-spdm]
./sniffer
```
- (2th) Wireshark, with the dissector installed and filter "tcp.port == 2323 && tcp.flags.push == 1"
```bash
[th-duvanel@~/riscv-spdm]
sudo wireshark
```
- (3th) The emulator
```bash
[th-duvanel@~/riscv-spdm]
./run.sh
```

## Tested in

```bash
OS: Ubuntu 22.04.4 LTS x86_64 
Kernel: 6.5.0-26-generic 
Shell: zsh 5.8.1 
DE: GNOME 42.9 
Terminal: gnome-terminal 
CPU: 12th Gen Intel i5-12500H (16)  
GPU: NVIDIA GeForce RTX 3050 Mobile 
Memory: 6359MiB / 15668MiB 

```