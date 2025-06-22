#!/bin/bash
# Quick script to run the VM

echo "Starting QEMU VM with hardening kernel..."
echo "Press Ctrl-A X to exit the VM"
echo ""

qemu-system-x86_64 \
    -kernel arch/x86/boot/bzImage \
    -initrd test-initramfs.cpio.gz \
    -append "console=ttyS0 init=/init loglevel=4" \
    -nographic \
    -m 512M \
    -cpu qemu64