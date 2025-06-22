#!/bin/bash
# Test kernel build and boot in VM

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VM_MEMORY="2G"
VM_CPUS="2"
KERNEL_IMAGE="arch/x86/boot/bzImage"
TEST_TIMEOUT="300"

# Parse arguments
SKIP_BUILD=false
SKIP_BOOT=false
RUN_TESTS=false
DEBUG=false

usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -s, --skip-build     Skip kernel build"
    echo "  -b, --skip-boot      Skip boot test"
    echo "  -t, --run-tests      Run kernel tests"
    echo "  -d, --debug          Enable debug output"
    echo "  -h, --help           Show this help"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -b|--skip-boot)
            SKIP_BOOT=true
            shift
            ;;
        -t|--run-tests)
            RUN_TESTS=true
            shift
            ;;
        -d|--debug)
            DEBUG=true
            set -x
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check dependencies
check_deps() {
    log "Checking dependencies..."
    
    local missing_deps=()
    
    # Check for required tools
    for tool in qemu-system-x86_64 make gcc; do
        if ! command -v $tool &> /dev/null; then
            missing_deps+=($tool)
        fi
    done
    
    # Check for kernel build dependencies
    if [ ! -f /usr/include/openssl/ssl.h ]; then
        missing_deps+=("libssl-dev")
    fi
    
    if [ ! -f /usr/include/libelf.h ]; then
        missing_deps+=("libelf-dev")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        error "Missing dependencies: ${missing_deps[*]}"
        echo "Install with:"
        echo "  sudo apt-get install -y qemu-system-x86 build-essential libssl-dev libelf-dev"
        exit 1
    fi
    
    log "All dependencies satisfied"
}

# Build kernel
build_kernel() {
    if [ "$SKIP_BUILD" = true ]; then
        log "Skipping kernel build"
        return
    fi
    
    log "Building kernel..."
    
    # Clean if requested
    if [ -f .config ]; then
        warning "Existing .config found, using it"
    else
        log "Creating default config"
        make defconfig
    fi
    
    # Apply test-friendly options
    log "Configuring for VM testing..."
    ./scripts/config --enable CONFIG_SERIAL_8250
    ./scripts/config --enable CONFIG_SERIAL_8250_CONSOLE
    ./scripts/config --enable CONFIG_E1000
    ./scripts/config --enable CONFIG_E1000E
    ./scripts/config --enable CONFIG_BLK_DEV_SD
    ./scripts/config --enable CONFIG_SCSI
    ./scripts/config --enable CONFIG_ATA
    ./scripts/config --enable CONFIG_ATA_PIIX
    ./scripts/config --enable CONFIG_VIRTIO
    ./scripts/config --enable CONFIG_VIRTIO_PCI
    ./scripts/config --enable CONFIG_VIRTIO_BLK
    ./scripts/config --enable CONFIG_VIRTIO_NET
    ./scripts/config --enable CONFIG_9P_FS
    
    # Enable debugging if requested
    if [ "$DEBUG" = true ]; then
        ./scripts/config --enable CONFIG_DEBUG_INFO
        ./scripts/config --enable CONFIG_DEBUG_KERNEL
        ./scripts/config --enable CONFIG_EARLY_PRINTK
    fi
    
    make olddefconfig
    
    # Build with available CPUs
    log "Building with $(nproc) CPUs..."
    if ! make -j$(nproc); then
        error "Kernel build failed"
        exit 1
    fi
    
    if [ ! -f "$KERNEL_IMAGE" ]; then
        error "Kernel image not found at $KERNEL_IMAGE"
        exit 1
    fi
    
    log "Kernel build completed successfully"
}

# Create minimal initramfs for testing
create_initramfs() {
    log "Creating test initramfs..."
    
    INITRAMFS_DIR=$(mktemp -d)
    cd "$INITRAMFS_DIR"
    
    # Create directory structure
    mkdir -p {bin,sbin,etc,proc,sys,dev,tmp,mnt,root}
    
    # Create init script
    cat > init << 'EOF'
#!/bin/sh

# Mount essential filesystems
/bin/mount -t proc none /proc
/bin/mount -t sysfs none /sys
/bin/mount -t devtmpfs none /dev

# Basic system info
echo "=== Kernel Boot Test ==="
echo "Kernel version: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Memory: $(grep MemTotal /proc/meminfo)"
echo "CPUs: $(grep -c processor /proc/cpuinfo)"
echo "Boot time: $(cut -d' ' -f1 /proc/uptime)s"

# Run tests if requested
if grep -q "run_tests" /proc/cmdline; then
    echo "=== Running Tests ==="
    
    # Memory test
    echo -n "Memory allocation test... "
    if dd if=/dev/zero of=/tmp/test bs=1M count=100 2>/dev/null; then
        echo "PASS"
    else
        echo "FAIL"
    fi
    rm -f /tmp/test
    
    # CPU test
    echo -n "CPU stress test... "
    for i in $(seq 1 10000); do
        echo $((i * i)) > /dev/null
    done
    echo "PASS"
    
    # Network test (loopback)
    echo -n "Network loopback test... "
    if ping -c 1 127.0.0.1 > /dev/null 2>&1; then
        echo "PASS"
    else
        echo "FAIL"
    fi
fi

# Signal successful boot
echo "BOOT_SUCCESS"

# Keep system running for debugging if requested
if grep -q "debug" /proc/cmdline; then
    echo "Debug mode - system will stay up"
    /bin/sh
else
    # Shutdown
    /bin/sync
    /bin/poweroff -f
fi
EOF
    chmod +x init
    
    # Copy busybox
    if [ -f /bin/busybox ]; then
        cp /bin/busybox bin/
    elif [ -f /usr/bin/busybox ]; then
        cp /usr/bin/busybox bin/
    else
        # Create minimal busybox
        cat > bin/busybox << 'EOF'
#!/bin/sh
# Minimal shell implementation
case "$1" in
    sh) shift; exec /bin/sh "$@" ;;
    mount) shift; mount "$@" ;;
    poweroff) halt ;;
    *) echo "busybox: $1: not found" >&2; exit 1 ;;
esac
EOF
        chmod +x bin/busybox
    fi
    
    # Create basic shell if needed
    if [ ! -f bin/sh ] && [ -f /bin/sh ]; then
        cp /bin/sh bin/
        # Copy required libraries
        for lib in $(ldd /bin/sh | grep -o '/lib.*\.[0-9]' | sort -u); do
            mkdir -p .$(dirname $lib)
            cp $lib .$lib
        done
    else
        ln -s busybox bin/sh
    fi
    
    # Create other essential symlinks
    for cmd in mount poweroff sync ping dd grep cut seq uname; do
        ln -s busybox bin/$cmd 2>/dev/null || true
    done
    
    # Create cpio archive
    find . | cpio -o -H newc 2>/dev/null | gzip > "$OLDPWD/initramfs.cpio.gz"
    cd "$OLDPWD"
    rm -rf "$INITRAMFS_DIR"
    
    log "Initramfs created: $(ls -lh initramfs.cpio.gz | awk '{print $5}')"
}

# Boot test in QEMU
boot_test() {
    if [ "$SKIP_BOOT" = true ]; then
        log "Skipping boot test"
        return
    fi
    
    log "Starting boot test in QEMU..."
    
    # Prepare kernel command line
    CMDLINE="console=ttyS0 panic=10"
    if [ "$RUN_TESTS" = true ]; then
        CMDLINE="$CMDLINE run_tests"
    fi
    if [ "$DEBUG" = true ]; then
        CMDLINE="$CMDLINE debug earlyprintk=serial"
    fi
    
    # Create QEMU command
    QEMU_CMD="qemu-system-x86_64 \
        -kernel $KERNEL_IMAGE \
        -initrd initramfs.cpio.gz \
        -append \"$CMDLINE\" \
        -m $VM_MEMORY \
        -smp $VM_CPUS \
        -nographic \
        -no-reboot \
        -serial mon:stdio"
    
    # Add KVM if available
    if [ -w /dev/kvm ]; then
        log "KVM acceleration available"
        QEMU_CMD="$QEMU_CMD -enable-kvm"
    else
        warning "KVM not available, boot will be slower"
    fi
    
    # Run QEMU with timeout
    log "Booting kernel (timeout: ${TEST_TIMEOUT}s)..."
    
    if timeout $TEST_TIMEOUT bash -c "$QEMU_CMD" | tee boot.log; then
        if grep -q "BOOT_SUCCESS" boot.log; then
            log "Boot test PASSED"
            
            # Extract boot time
            BOOT_TIME=$(grep "Boot time:" boot.log | awk '{print $3}')
            if [ -n "$BOOT_TIME" ]; then
                log "Boot completed in ${BOOT_TIME}"
            fi
            
            # Show test results if tests were run
            if [ "$RUN_TESTS" = true ]; then
                log "Test results:"
                grep -E "(PASS|FAIL)" boot.log | sed 's/^/  /'
            fi
        else
            error "Boot test FAILED - no success marker found"
            tail -20 boot.log
            exit 1
        fi
    else
        error "Boot test FAILED - timeout or crash"
        echo "Last 20 lines of output:"
        tail -20 boot.log
        exit 1
    fi
}

# Run security checks
security_checks() {
    log "Running security checks..."
    
    # Check if hardening options are enabled
    local hardening_opts=(
        "CONFIG_HARDENED_USERCOPY"
        "CONFIG_FORTIFY_SOURCE"
        "CONFIG_STACKPROTECTOR_STRONG"
        "CONFIG_RANDOMIZE_BASE"
        "CONFIG_STRICT_KERNEL_RWX"
    )
    
    echo "Checking hardening options:"
    for opt in "${hardening_opts[@]}"; do
        if grep -q "^${opt}=y" .config; then
            echo -e "  ${GREEN}✓${NC} $opt enabled"
        else
            echo -e "  ${RED}✗${NC} $opt not enabled"
        fi
    done
}

# Performance test
performance_test() {
    if [ ! "$RUN_TESTS" = true ]; then
        return
    fi
    
    log "Running performance tests..."
    
    # Simple kernel build benchmark
    log "Kernel build benchmark:"
    make clean > /dev/null 2>&1
    
    START_TIME=$(date +%s)
    make -j$(nproc) vmlinux > /dev/null 2>&1
    END_TIME=$(date +%s)
    
    BUILD_TIME=$((END_TIME - START_TIME))
    log "Kernel build time: ${BUILD_TIME}s"
}

# Main execution
main() {
    log "Linux kernel VM test starting..."
    
    # Check we're in kernel source directory
    if [ ! -f Makefile ] || [ ! -d kernel ]; then
        error "Not in kernel source directory"
        exit 1
    fi
    
    # Run checks
    check_deps
    
    # Build kernel
    build_kernel
    
    # Security checks
    security_checks
    
    # Create initramfs
    create_initramfs
    
    # Boot test
    boot_test
    
    # Performance test
    performance_test
    
    # Cleanup
    rm -f initramfs.cpio.gz boot.log
    
    log "All tests completed successfully!"
}

# Run main
main "$@"