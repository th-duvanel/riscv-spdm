# RISC-V 64 bits with LibSPDM on QEMU

This repository is a fork of an implementation of LibSPDM inside QEMU and Das U-Boot specifically for RISC-V 64 bits.
Please, access the original project and give it a star.
This is just a modification to proper run with an opened socket in VirtIO to export packets to an echo server in TCP port 2323
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
I know, it is strange to have a Makefile in the repo and still have to use a shell script. This is because the Git repos (buildroot, qemu, etc.) have to compile themselves individually, calling recursively their own Makefiles. If compiled together, some unexpected errors can appear, so, use the script above.

In compile.sh, you will compile the C binary to receive the TCP packets sent by the QEMU, so Wireshark detects them
properly and without any inconsistency UDP can bring.


For the qemu emulation, you need to simulate the disk, so, use this shell script.
```bash
[th-duvanel@~/spdm-wid/riscv-spdm]
./newdisk.sh
```
I'm sorry for the sudo newdisk.sh inside the own shell. It is because the compilation and environment variables aren't the same if you're running the
script with and without it. If you want it, you can open the .sh and run the commands separately.

If you restart your computer, you need to run again the environemnt variables:

```bash
[th-duvanel@~/riscv-spdm]
. ./env.sh
```

# Running

Now, run in this order, inside the riscv-spdm folder:
- (1st) The sniffer (server, echo, etc.), make sure you have the 2323 TCP port on
```bash
[th-duvanel@~/spdm-wid/riscv-spdm]
./sniffer
```
- (2nd) Wireshark, with the dissector installed and filter "tcp.port == 2323 && tcp.flags.push == 1"
```bash
[th-duvanel@~/spdm-wid/riscv-spdm]
sudo wireshark
```
- (3th) The emulator
```bash
[th-duvanel@~/spdm-wid/riscv-spdm]
./run.sh
```

## Possible errors

Errors can occur on any type of software, principally on those that depend on other devs software.
This repository happens to need a lot of dependencies, which can be malformed or not compiled properly. The script that you use to compile riscv-spdm will tell if something is missing, like a binary or a folder.

For example:

```bash
[th-duvanel@~/spdm-wid/riscv-spdm]
./compile.sh
Error: riscv64-linux- wasn't found. Compile buildroot first.
```

The error above is related to the riscv64 and buildroot, one of the emulation dependencies (all dependencies are important!), so, you can try to run it again, writing:

```bash
[th-duvanel@~/spdm-wid/riscv-spdm]
make broot
```

Now that you understand, this table will show that for each error, there is a make command.
If a make is not enough, probably you didn't set the environment variables properly.

| Error | Recommended command |
|----------|----------|
| riscv64 not found!   | make broot   |
| u-boot not found!   | make uboot   |
| other errors   | . ./env.sh   |
| nothing above works   | make clean, RESTART!   |


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
