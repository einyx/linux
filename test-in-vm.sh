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
    ./scripts/config --disable CONFIG_DRM_I915
    ./scripts/config --enable CONFIG_HARDENED_USERCOPY
    
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
    
    # Create init script - try static approach
    cat > init << 'EOF'
#!/bin/busybox sh

echo "=== Kernel Boot Test ==="

# Try to mount basic filesystems
busybox mount -t proc none /proc 2>/dev/null || echo "proc mount failed"
busybox mount -t sysfs none /sys 2>/dev/null || echo "sysfs mount failed"

# Basic system info  
echo "Kernel version: $(busybox uname -r)"
echo "Architecture: $(busybox uname -m)"

if [ -f /proc/meminfo ]; then
    echo "Memory: $(busybox grep MemTotal /proc/meminfo)"
fi

if [ -f /proc/cpuinfo ]; then
    echo "CPUs: $(busybox grep -c processor /proc/cpuinfo)"
fi

if [ -f /proc/uptime ]; then
    echo "Boot time: $(busybox cut -d' ' -f1 /proc/uptime)s"
fi

# Signal successful boot
echo "BOOT_SUCCESS"

# Simple shutdown
busybox sync
busybox poweroff -f
EOF
    chmod +x init
    
    # Try to use the host's busybox first (static binary)
    if command -v busybox >/dev/null 2>&1; then
        cp $(command -v busybox) bin/busybox
        chmod +x bin/busybox
        # Use busybox as shell  
        ln -s busybox bin/sh
    else
        # Copy host shell and libraries (original approach but better)
        if [ -f /bin/dash ]; then
            # Use dash if available (smaller, static-friendly)
            cp /bin/dash bin/sh
        elif [ -f /bin/sh ]; then
            cp /bin/sh bin/sh
        else
            echo "No suitable shell found" >&2
            exit 1
        fi
        chmod +x bin/sh
        
        # Copy required libraries
        mkdir -p lib lib64 lib/x86_64-linux-gnu
        for lib in $(ldd bin/sh 2>/dev/null | grep -o '/lib[^ ]*' | sort -u); do
            if [ -f "$lib" ]; then
                cp "$lib" ".${lib}" 2>/dev/null || true
            fi
        done
        
        # Create minimal busybox wrapper
        cat > bin/busybox << 'EOF'
#!/bin/sh
exec /bin/sh "$@"
EOF
        chmod +x bin/busybox
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
    
    # Prepare kernel command line with explicit init
    CMDLINE="console=ttyS0 panic=10 init=/init"
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