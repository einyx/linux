#!/bin/bash
# Fixed boot test script

set -e

echo "Creating minimal initramfs..."

# Create a temporary directory
INITRAMFS_DIR=$(mktemp -d)
cd "$INITRAMFS_DIR"

# Create init script that uses built-in shell commands only
cat > init << 'EOF'
#!/bin/sh
echo "Kernel boot test starting..."
echo "BOOT_SUCCESS"
sync
poweroff -f 2>/dev/null || halt -f 2>/dev/null || echo "Cannot halt"
while true; do sleep 1; done
EOF
chmod +x init

# Create the initramfs
find . | cpio -o -H newc 2>/dev/null | gzip > "$OLDPWD/test-initramfs.cpio.gz"
cd "$OLDPWD"
rm -rf "$INITRAMFS_DIR"

echo "Testing kernel boot..."

# Run QEMU with fixed serial options
timeout 30 qemu-system-x86_64 \
    -kernel arch/x86/boot/bzImage \
    -initrd test-initramfs.cpio.gz \
    -append "console=ttyS0 panic=1 rdinit=/init" \
    -m 512M \
    -nographic \
    -no-reboot \
    -serial mon:stdio \
    2>&1 | tee test-boot.log

# Check if boot was successful
if grep -q "BOOT_SUCCESS" test-boot.log; then
    echo "Boot test PASSED"
    exit 0
else
    echo "Boot test FAILED"
    echo "=== Boot log ==="
    cat test-boot.log
    exit 1
fi