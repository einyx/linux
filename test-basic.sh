#!/bin/bash
# Basic tests without full kernel build

set -e

echo "=== Basic Kain Kernel Tests ==="
echo ""

# Check environment
echo "Checking environment..."
echo "- Current directory: $(pwd)"
echo "- Kernel detected: $([ -f Makefile ] && grep "^VERSION" Makefile | head -3 | tr '\n' '.' | sed 's/[^0-9.]//g')"
echo "- Git branch: $(git branch --show-current 2>/dev/null || echo 'not in git')"
echo ""

# Test configuration
echo "Testing kernel configuration..."
if make defconfig > /dev/null 2>&1; then
    echo "✓ Default config created"
    
    # Check security options
    echo ""
    echo "Security options in default config:"
    for opt in CONFIG_STACKPROTECTOR_STRONG CONFIG_RANDOMIZE_BASE CONFIG_STRICT_KERNEL_RWX; do
        if grep -q "^${opt}=y" .config; then
            echo "  ✓ $opt enabled"
        else
            echo "  ✗ $opt not enabled"
        fi
    done
else
    echo "✗ Failed to create config"
fi

# Test GitHub workflows
echo ""
echo "Validating GitHub Actions workflows..."
for workflow in .github/workflows/*.yml; do
    if [ -f "$workflow" ]; then
        name=$(basename "$workflow")
        if python3 -c "import yaml; yaml.safe_load(open('$workflow'))" 2>/dev/null; then
            echo "  ✓ $name valid"
        else
            echo "  ✗ $name invalid"
        fi
    fi
done

# Test scripts
echo ""
echo "Checking test scripts..."
for script in *.sh; do
    if [ -x "$script" ]; then
        echo "  ✓ $script is executable"
    else
        echo "  ✗ $script not executable"
    fi
done

# Quick build test
echo ""
echo "Testing minimal build..."
if make scripts/basic/fixdep > /dev/null 2>&1; then
    echo "✓ Build system working"
else
    echo "✗ Build system not working"
fi

echo ""
echo "=== Basic tests completed ==="
echo ""
echo "For full testing, run:"
echo "  ./test-in-vm.sh    # Full VM boot test"
echo "  ./quick-test.sh    # More thorough checks"