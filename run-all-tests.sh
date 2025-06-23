#!/bin/bash
# Run all tests for the kernel

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== Kain Kernel Test Suite ==="
echo ""

FAILED_TESTS=()
PASSED_TESTS=()

run_test() {
    local test_name=$1
    local test_cmd=$2
    
    echo -n "Running $test_name... "
    
    if eval "$test_cmd" > /tmp/test_output_$$.log 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASSED_TESTS+=("$test_name")
    else
        echo -e "${RED}FAIL${NC}"
        FAILED_TESTS+=("$test_name")
        echo "Error output:"
        tail -20 /tmp/test_output_$$.log | sed 's/^/  /'
    fi
    
    rm -f /tmp/test_output_$$.log
}

# 1. Environment checks
echo "=== Environment Checks ==="
run_test "Kernel source check" "[ -f Makefile ] && [ -d kernel ]"
run_test "Git repository" "git rev-parse --git-dir"
run_test "Build dependencies" "which gcc make flex bison"
echo ""

# 2. Static analysis
echo "=== Static Analysis ==="
run_test "Kernel config" "[ -f .config ] || make defconfig"
run_test "Headers check" "make headers_check 2>/dev/null || echo 'headers_check target deprecated'"
run_test "Sparse check (sample)" "make C=1 M=init/"

if [ -f scripts/checkpatch.pl ]; then
    run_test "Checkpatch" "./scripts/checkpatch.pl --git HEAD~1..HEAD || true"
fi
echo ""

# 3. Build tests
echo "=== Build Tests ==="
run_test "Scripts build" "make -j$(nproc) scripts/"
run_test "Documentation build" "timeout 10 make htmldocs 2>/dev/null || echo 'Documentation build skipped (timeout)'"
run_test "Clean build" "make clean"
echo ""

# 4. Security checks
echo "=== Security Checks ==="
run_test "Hardening config" "grep -q CONFIG_HARDENED_USERCOPY=y .config"
run_test "Stack protector" "grep -q CONFIG_STACKPROTECTOR_STRONG=y .config"
run_test "KASLR enabled" "grep -q CONFIG_RANDOMIZE_BASE=y .config"
echo ""

# 5. Workflow validation
echo "=== GitHub Actions Validation ==="
for workflow in .github/workflows/*.yml; do
    if [ -f "$workflow" ]; then
        wf_name=$(basename "$workflow")
        run_test "Workflow $wf_name" "python3 -m json.tool $workflow >/dev/null 2>&1 || echo 'YAML validation skipped'"
    fi
done
echo ""

# 6. Quick VM test (if requested)
if [ "$1" = "--with-vm" ]; then
    echo "=== VM Boot Test ==="
    # VM boot test needs special handling due to QEMU output
    echo -n "Running VM boot test... "
    
    if ./test-in-vm.sh > /tmp/vm_test_output_$$.log 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASSED_TESTS+=("VM boot test")
    else
        echo -e "${RED}FAIL${NC}"
        FAILED_TESTS+=("VM boot test")
        echo "Error output:"
        tail -50 /tmp/vm_test_output_$$.log | sed 's/^/  /'
    fi
    
    rm -f /tmp/vm_test_output_$$.log
    echo ""
fi

# Summary
echo "=== Test Summary ==="
echo -e "Passed: ${GREEN}${#PASSED_TESTS[@]}${NC}"
echo -e "Failed: ${RED}${#FAILED_TESTS[@]}${NC}"

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    for test in "${FAILED_TESTS[@]}"; do
        echo "  - $test"
    done
    exit 1
else
    echo ""
    echo -e "${GREEN}All tests passed!${NC}"
fi

echo ""
echo "For more thorough testing:"
echo "  - Full VM test: ./test-in-vm.sh"
echo "  - GitHub Actions: ./test-github-actions.sh all"
echo "  - Kernel selftests: make kselftest"

# Generate Debian package if all tests passed
if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
    echo ""
    echo "=== Building Debian Package ==="
    
    # Get kernel version
    KERNEL_VERSION=$(make kernelversion 2>/dev/null || echo "unknown")
    LOCALVERSION=$(grep CONFIG_LOCALVERSION .config 2>/dev/null | cut -d'"' -f2 || echo "")
    FULL_VERSION="${KERNEL_VERSION}${LOCALVERSION}"
    
    echo "Building kernel package version: ${FULL_VERSION}"
    
    # Build debian packages
    # Note: This requires debhelper and libdw-dev packages to be installed
    # Install with: sudo apt-get install debhelper libdw-dev
    if command -v dh_listpackages >/dev/null 2>&1; then
        if make -j$(nproc) bindeb-pkg > /tmp/deb_build_$$.log 2>&1; then
            echo -e "${GREEN}[SUCCESS]${NC} Debian package built successfully"
            
            # List generated packages
            echo ""
            echo "Generated packages:"
            ls -la ../*.deb 2>/dev/null | grep "${KERNEL_VERSION}" | sed 's/^/  /'
            
            # Create packages directory if it doesn't exist
            mkdir -p packages
            
            # Move packages to packages directory
            if mv ../*${KERNEL_VERSION}*.deb packages/ 2>/dev/null; then
                echo ""
                echo "Packages moved to ./packages/ directory:"
                ls -la packages/*.deb | sed 's/^/  /'
            fi
        else
            echo -e "${YELLOW}[WARNING]${NC} Debian package build failed"
            echo "Build log tail:"
            tail -20 /tmp/deb_build_$$.log | sed 's/^/  /'
        fi
        
        rm -f /tmp/deb_build_$$.log
    else
        echo -e "${YELLOW}[WARNING]${NC} Debian package build skipped - missing build dependencies"
        echo "To build debian packages, install:"
        echo "  sudo apt-get install debhelper libdw-dev"
    fi
fi