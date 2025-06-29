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
    
    # First try to create a minimal static init binary
    cat > test-init.c << 'EOF'
#include <unistd.h>
#include <sys/reboot.h>
#include <linux/reboot.h>

int main() {
    const char *msg1 = "=== Kernel Boot Test ===\n";
    const char *msg2 = "BOOT_SUCCESS\n";
    
    write(1, msg1, 25);
    write(1, msg2, 13);
    
    sync();
    
    /* Try multiple shutdown methods */
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    reboot(LINUX_REBOOT_CMD_HALT);
    
    /* If still here, just exit */
    return 0;
}
EOF
    
    # Try to compile statically
    if command -v gcc >/dev/null 2>&1 && gcc -static -o test-init test-init.c 2>/dev/null; then
        log "Using static C init"
        mkdir -p minimal-initramfs
        cp test-init minimal-initramfs/init
        (cd minimal-initramfs && echo init | cpio -o -H newc | gzip > ../initramfs.cpio.gz)
        rm -rf minimal-initramfs test-init test-init.c
    else
        # Fallback to busybox approach
        INITRAMFS_DIR=$(mktemp -d)
        cd "$INITRAMFS_DIR"
        
        # Create directory structure
        mkdir -p {bin,sbin,etc,proc,sys,dev,tmp,mnt,root}
        
        if [ -f /usr/bin/busybox-static ]; then
            log "Using busybox-static for initramfs"
            cp /usr/bin/busybox-static bin/busybox
        elif command -v busybox >/dev/null 2>&1; then
            log "Using host busybox"
            cp $(command -v busybox) bin/busybox
        else
            error "No suitable init method found"
            exit 1
        fi
        
        chmod +x bin/busybox
        
        # Create symlinks
        for cmd in sh echo mount umount sync poweroff halt reboot; do
            ln -s busybox bin/$cmd
        done
        
        # Create init script
        cat > init << 'EOF'
#!/bin/sh
echo "=== Kernel Boot Test ==="
echo "BOOT_SUCCESS"
sync
poweroff -f 2>/dev/null || halt -f 2>/dev/null || echo "Cannot halt"
EOF
        chmod +x init
        
        # Create cpio archive
        find . | cpio -o -H newc 2>/dev/null | gzip > "$OLDPWD/initramfs.cpio.gz"
        cd "$OLDPWD"
        rm -rf "$INITRAMFS_DIR"
    fi
    
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
    CMDLINE="console=ttyS0 panic=10 rdinit=/init earlyprintk=serial,ttyS0,115200"
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
        QEMU_CMD="$QEMU_CMD -enable-kvm -cpu host"
    else
        warning "KVM not available, boot will be slower"
        QEMU_CMD="$QEMU_CMD -cpu qemu64"
    fi
    
    # Run QEMU with timeout
    log "Booting kernel (timeout: ${TEST_TIMEOUT}s)..."
    
    # Run boot test with timeout, allowing for halted state
    if timeout $TEST_TIMEOUT bash -c "$QEMU_CMD" 2>&1 | tee boot.log || true; then
        # Check for success marker
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
            
            # Success even if poweroff didn't work perfectly
            return 0
        else
            error "Boot test FAILED - no success marker found"
            tail -20 boot.log
            exit 1
        fi
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
    
    # Cleanup - only remove temporary files, keep boot.log for debugging
    rm -f initramfs.cpio.gz
    
    log "All tests completed successfully!"
}

# Run main
main "$@"