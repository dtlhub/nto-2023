#!/bin/sh
#
qemu-system-x86_64 \
    -m 512M \
    -nographic \
    -kernel /task/kernel/bzImage \
    -append "console=ttyS0 loglevel=6 oops=panic kaslr kpti=1 panic=-1" \
    -no-reboot \
    -cpu qemu64,+smep,+smap \
    -smp 1 \
    -monitor none \
    -initrd initramfs.cpio.gz \
