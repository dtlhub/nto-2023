#!/usr/bin/env bash
cp module/vuln.ko ./root/root/vuln.ko
gcc exploit.c -static -o expl
cp expl root

cd root
find . -print0 | cpio -o --format=newc --null > ../rootfs_updated.cpio
cd ..
./run.sh
