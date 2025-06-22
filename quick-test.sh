#!/bin/bash
# Quick kernel build and test

set -e

echo "=== Quick Kernel Test ==="

# Check if we're in kernel directory
if [ ! -f Makefile ] || [ ! -d kernel ]; then
    echo "Error: Not in kernel source directory"
    exit 1
fi

# Quick build test
echo "1. Testing kernel configuration..."
make defconfig > /dev/null 2>&1
echo "✓ Configuration successful"

echo "2. Testing partial build..."
make -j$(nproc) scripts/ > /dev/null 2>&1
echo "✓ Scripts build successful"

echo "3. Testing kernel headers..."
make -j$(nproc) headers_check > /dev/null 2>&1 || true
echo "✓ Headers check completed"

echo "4. Running checkpatch on recent commits..."
if git rev-parse --git-dir > /dev/null 2>&1; then
    git log --oneline -5
    ./scripts/checkpatch.pl --git HEAD~1..HEAD || true
else
    echo "Not a git repository, skipping commit checks"
fi

echo "5. Checking for common issues..."
# Check for missing dependencies
MISSING_DEPS=""
for dep in gcc make flex bison libssl-dev libelf-dev; do
    if ! dpkg -l | grep -q "^ii  $dep"; then
        MISSING_DEPS="$MISSING_DEPS $dep"
    fi
done

if [ -n "$MISSING_DEPS" ]; then
    echo "⚠ Missing dependencies:$MISSING_DEPS"
    echo "Install with: sudo apt-get install$MISSING_DEPS"
else
    echo "✓ All dependencies installed"
fi

# Check kernel version
KERNEL_VERSION=$(make kernelversion 2>/dev/null)
echo ""
echo "Kernel version: $KERNEL_VERSION"
echo "Architecture: $(uname -m)"
echo "Compiler: $(gcc --version | head -1)"
echo ""

# Simple syntax check
echo "6. Checking for syntax errors..."
find . -name "*.c" -type f | head -20 | while read file; do
    gcc -fsyntax-only -w "$file" 2>/dev/null || echo "⚠ Syntax error in $file"
done
echo "✓ Syntax check completed"

echo ""
echo "=== Quick test completed ==="
echo ""
echo "For full VM boot test, run: ./test-in-vm.sh"
echo "For specific subsystem: make M=drivers/gpu/drm"
echo "For all tests: make kselftest"