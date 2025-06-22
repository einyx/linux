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
run_test "Kernel config" "make defconfig"
run_test "Headers check" "make headers_check"
run_test "Sparse check (sample)" "make C=1 M=init/"

if [ -f scripts/checkpatch.pl ]; then
    run_test "Checkpatch" "./scripts/checkpatch.pl --git HEAD~1..HEAD"
fi
echo ""

# 3. Build tests
echo "=== Build Tests ==="
run_test "Scripts build" "make -j$(nproc) scripts/"
run_test "Documentation build" "make htmldocs" || true
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
        run_test "Workflow $wf_name" "python3 -c 'import yaml; yaml.safe_load(open(\"$workflow\"))'"
    fi
done
echo ""

# 6. Quick VM test (if requested)
if [ "$1" = "--with-vm" ]; then
    echo "=== VM Boot Test ==="
    run_test "VM boot test" "./test-in-vm.sh --skip-build"
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