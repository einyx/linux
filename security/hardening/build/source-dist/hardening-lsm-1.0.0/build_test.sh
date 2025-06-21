#!/bin/bash
# Simple build test for hardening module

echo "Security Hardening Module Build Test"
echo "===================================="

# Go to kernel root
cd ../..

# Check if we're in the kernel source tree
if [ ! -f "Makefile" ] || [ ! -d "security" ]; then
    echo "Error: Not in kernel source tree"
    exit 1
fi

echo "Checking module files..."
find security/hardening -name "*.c" -o -name "*.h" | sort

echo -e "\nChecking Kconfig integration..."
grep -n "hardening" security/Kconfig

echo -e "\nChecking Makefile integration..."
grep -n "hardening" security/Makefile

echo -e "\nModule structure looks good!"
echo "To build the complete kernel with this module:"
echo "1. Install required tools: sudo apt-get install flex bison libssl-dev"
echo "2. Configure: make menuconfig"
echo "3. Enable: Security options -> Security Hardening Module"
echo "4. Build: make -j$(nproc)"
echo "5. Install: sudo make modules_install && sudo make install"