#!/bin/bash
# Boot test with static init binary

set -e

echo "Compiling static init..."
gcc -static -o test-init test-init.c

echo "Creating minimal initramfs..."

# Create a temporary directory
INITRAMFS_DIR=$(mktemp -d)
cd "$INITRAMFS_DIR"

# Copy static init
cp "$OLDPWD/test-init" init
chmod +x init

# Create the initramfs
find . | cpio -o -H newc 2>/dev/null | gzip > "$OLDPWD/test-initramfs.cpio.gz"
cd "$OLDPWD"
rm -rf "$INITRAMFS_DIR"

echo "Testing kernel boot..."

# Run QEMU
timeout 30 qemu-system-x86_64 \
    -kernel arch/x86/boot/bzImage \
    -initrd test-initramfs.cpio.gz \
    -append "console=ttyS0 panic=1" \
    -m 512M \
    -nographic \
    -no-reboot \
    -serial mon:stdio \
    2>&1 | tee test-boot.log

# Check if boot was successful
if grep -q "BOOT_SUCCESS" test-boot.log; then
    echo "✓ Boot test PASSED"
    # Clean up
    rm -f test-init test-initramfs.cpio.gz test-boot.log
    exit 0
else
    echo "✗ Boot test FAILED"
    exit 1
fi