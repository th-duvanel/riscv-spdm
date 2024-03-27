# RISC-V 64 bits with LibSPDM on QEMU

This repository is a fork of an implementation of LibSPDM inside QEMU and Das U-Boot especifically for RISC-V 64 bits.
Please, access the original project and give it a star.
This is just a modification to proper run with a opened socket in VirtIO to export packets to a echo server in TCP port 2323
(spdm_sniffer.c).

Then, you can read those packets with Wireshark, using the SPDM-WID dissector.

# Compilation Steps

## Initial Configuration

First, you need some dependencies:

```bash
$ chmod +x *.sh
$ sudo ./deps.sh
$ . ./env.sh
```

Run a make that will do everything for you.
SPOILER: it will take some time. Be patient.

```bash
$  make
```

# Running

For the qemu emulation, run in this order:
```bash
$ sudo ./newdisk.sh
$ ./run.sh
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