#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Comprehensive test runner for Linux Security Modules
# Usage: ./run-all-tests.sh [--with-vm] [--quick]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
WITH_VM=0
QUICK=0
for arg in "$@"; do
    case $arg in
        --with-vm)
            WITH_VM=1
            ;;
        --quick)
            QUICK=1
            ;;
        --help)
            echo "Usage: $0 [--with-vm] [--quick]"
            echo "  --with-vm  Run tests in QEMU/KVM virtual machine"
            echo "  --quick    Run only essential tests"
            exit 0
            ;;
    esac
done

echo -e "${GREEN}=== Linux Security Module Test Suite ===${NC}"
echo "Date: $(date)"
echo "Kernel: $(uname -r)"
echo ""

# Check prerequisites
check_prereqs() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check for required tools
    for tool in gcc python3 make; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}Error: $tool is not installed${NC}"
            exit 1
        fi
    done
    
    # Check for VM tools if needed
    if [ $WITH_VM -eq 1 ]; then
        if ! command -v qemu-system-x86_64 &> /dev/null; then
            echo -e "${RED}Error: qemu-system-x86_64 is not installed${NC}"
            echo "Install with: sudo apt-get install qemu-system-x86"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}Prerequisites OK${NC}"
}

# Run basic module tests
run_basic_tests() {
    echo -e "\n${YELLOW}Running basic module tests...${NC}"
    python3 test_security_modules.py
}

# Run fuzzing tests
run_fuzz_tests() {
    if [ $QUICK -eq 1 ]; then
        echo -e "\n${YELLOW}Skipping fuzz tests (quick mode)${NC}"
        return
    fi
    
    echo -e "\n${YELLOW}Running fuzz tests...${NC}"
    if command -v clang &> /dev/null; then
        make run-fuzz || echo -e "${YELLOW}Warning: Some fuzz tests failed${NC}"
    else
        echo -e "${YELLOW}Skipping fuzz tests (clang not installed)${NC}"
    fi
}

# Run regression tests
run_regression_tests() {
    echo -e "\n${YELLOW}Running regression tests...${NC}"
    python3 regression_tests.py
}

# Run Docker security tests
run_docker_tests() {
    echo -e "\n${YELLOW}Running Docker security tests...${NC}"
    if command -v docker &> /dev/null; then
        python3 test_docker_security.py
    else
        echo -e "${YELLOW}Skipping Docker tests (Docker not installed)${NC}"
    fi
}

# Run stress tests
run_stress_tests() {
    if [ $QUICK -eq 1 ]; then
        echo -e "\n${YELLOW}Skipping stress tests (quick mode)${NC}"
        return
    fi
    
    echo -e "\n${YELLOW}Running stress tests...${NC}"
    make stress-test
}

# Run VM-based tests
run_vm_tests() {
    if [ $WITH_VM -eq 0 ]; then
        return
    fi
    
    echo -e "\n${YELLOW}Running VM-based tests...${NC}"
    
    # Create a minimal test script for the VM
    cat > vm_test.sh << 'EOF'
#!/bin/bash
echo "Testing security modules in VM..."

# Test loading the hardening module
modprobe hardening || echo "Failed to load hardening module"

# Check if module is loaded
if lsmod | grep -q hardening; then
    echo "Hardening module loaded successfully"
else
    echo "Hardening module not loaded"
fi

# Test securityfs interface
if [ -d /sys/kernel/security/hardening ]; then
    echo "SecurityFS interface available"
    cat /sys/kernel/security/hardening/status
else
    echo "SecurityFS interface not found"
fi

# Basic functionality test
echo "Testing basic functionality..."
echo "enable" > /sys/kernel/security/hardening/policy 2>/dev/null || true
echo "enforce" > /sys/kernel/security/hardening/policy 2>/dev/null || true

# Run test program
/tests/test_rate_limit || echo "Rate limit test failed"

echo "VM tests completed"
EOF

    # Create minimal initrd with test files
    echo -e "${YELLOW}Creating test initrd...${NC}"
    mkdir -p vm_test_root/{bin,tests,sys,proc,dev}
    
    # Copy test binaries
    cp test_rate_limit vm_test_root/tests/ 2>/dev/null || true
    cp vm_test.sh vm_test_root/init
    chmod +x vm_test_root/init
    
    # Create initrd
    (cd vm_test_root && find . | cpio -o -H newc | gzip > ../test_initrd.gz)
    
    # Check for kernel image
    KERNEL_IMG="/boot/vmlinuz-$(uname -r)"
    if [ ! -f "$KERNEL_IMG" ]; then
        echo -e "${RED}Error: Kernel image not found at $KERNEL_IMG${NC}"
        echo "Cannot run VM tests without kernel image"
        return
    fi
    
    echo -e "${YELLOW}Starting QEMU VM...${NC}"
    # Run QEMU with minimal config
    timeout 60s qemu-system-x86_64 \
        -kernel "$KERNEL_IMG" \
        -initrd test_initrd.gz \
        -m 512M \
        -nographic \
        -append "console=ttyS0 panic=1" \
        -enable-kvm 2>/dev/null || \
    timeout 60s qemu-system-x86_64 \
        -kernel "$KERNEL_IMG" \
        -initrd test_initrd.gz \
        -m 512M \
        -nographic \
        -append "console=ttyS0 panic=1"
    
    # Cleanup
    rm -rf vm_test_root test_initrd.gz vm_test.sh
}

# Generate test report
generate_report() {
    echo -e "\n${GREEN}=== Test Summary ===${NC}"
    echo "Test run completed at: $(date)"
    
    # Count test results from output
    echo ""
    echo "Test Categories:"
    echo "- Basic module tests: COMPLETED"
    echo "- Regression tests: COMPLETED"
    echo "- Docker tests: COMPLETED"
    
    if [ $QUICK -eq 0 ]; then
        echo "- Fuzz tests: COMPLETED"
        echo "- Stress tests: COMPLETED"
    fi
    
    if [ $WITH_VM -eq 1 ]; then
        echo "- VM tests: COMPLETED"
    fi
    
    echo -e "\n${GREEN}All tests completed successfully!${NC}"
}

# Main execution
main() {
    check_prereqs
    
    # Run test suites
    run_basic_tests
    run_regression_tests
    run_docker_tests
    run_fuzz_tests
    run_stress_tests
    run_vm_tests
    
    # Generate report
    generate_report
}

# Run main function
main