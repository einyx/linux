# Building from Source

This guide covers building the Community Linux Kernel from source with various configurations.

## 📋 Prerequisites

### System Requirements
- **CPU**: 2+ cores (4+ recommended)
- **RAM**: 4GB minimum (8GB+ recommended)
- **Disk**: 25GB free space
- **OS**: Linux-based system

### Required Packages

#### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential git bc kmod cpio flex bison \
  libssl-dev libelf-dev libncurses-dev \
  dwarves zstd
```

#### Fedora/RHEL
```bash
sudo dnf install -y \
  gcc make git bc openssl-devel elfutils-libelf-devel \
  ncurses-devel bison flex perl-ExtUtils-MakeMaker \
  dwarves zstd
```

#### Arch Linux
```bash
sudo pacman -S --needed \
  base-devel git bc kmod cpio flex bison \
  openssl libelf ncurses pahole zstd
```

## 🚀 Quick Build

### 1. Clone Repository
```bash
git clone https://github.com/einyx/linux.git
cd linux
```

### 2. Configure
```bash
# Use distribution config as base
cp /boot/config-$(uname -r) .config
make olddefconfig

# Or start fresh with defaults
make defconfig
```

### 3. Build
```bash
# Build kernel and modules
make -j$(nproc)

# Build Debian packages
make -j$(nproc) deb-pkg

# Build RPM packages  
make -j$(nproc) rpm-pkg
```

## 🔒 Security-Hardened Build

### Apply Hardening Config
```bash
# Start with defconfig
make defconfig

# Apply security hardening
./scripts/kconfig/merge_config.sh .config \
  kernel/configs/hardening.config \
  kernel/configs/kvm_guest.config

# Review configuration
make menuconfig
```

### Recommended Security Options
```bash
# Enable via menuconfig or scripts/config
./scripts/config --enable CONFIG_HARDENED_USERCOPY
./scripts/config --enable CONFIG_FORTIFY_SOURCE
./scripts/config --enable CONFIG_STACKPROTECTOR_STRONG
./scripts/config --enable CONFIG_STRICT_KERNEL_RWX
./scripts/config --enable CONFIG_STRICT_MODULE_RWX
./scripts/config --enable CONFIG_INIT_ON_ALLOC_DEFAULT_ON
./scripts/config --enable CONFIG_RANDOMIZE_BASE

# Apply changes
make olddefconfig
```

## 🎯 Build Configurations

### Desktop/Workstation
```bash
make defconfig
./scripts/config --enable CONFIG_PREEMPT
./scripts/config --enable CONFIG_NO_HZ_FULL
./scripts/config --enable CONFIG_HIGH_RES_TIMERS
./scripts/config --module CONFIG_SOUND
./scripts/config --module CONFIG_SND
make olddefconfig
```

### Server
```bash
make defconfig
./scripts/config --enable CONFIG_PREEMPT_NONE
./scripts/config --enable CONFIG_NET_9P
./scripts/config --enable CONFIG_NUMA
./scripts/config --disable CONFIG_SOUND
./scripts/config --disable CONFIG_USB_HID
make olddefconfig
```

### Virtual Machine
```bash
make defconfig
./scripts/kconfig/merge_config.sh .config \
  kernel/configs/kvm_guest.config
./scripts/config --enable CONFIG_VIRTIO_NET
./scripts/config --enable CONFIG_VIRTIO_BLK
./scripts/config --enable CONFIG_VIRTIO_CONSOLE
make olddefconfig
```

### Embedded/Minimal
```bash
make tinyconfig
./scripts/config --enable CONFIG_NET
./scripts/config --enable CONFIG_INET
./scripts/config --enable CONFIG_SERIAL_8250
./scripts/config --enable CONFIG_SERIAL_8250_CONSOLE
make olddefconfig
```

## 🛠️ Advanced Building

### Cross-Compilation

#### ARM64 on x86_64
```bash
# Install cross-compiler
sudo apt-get install gcc-aarch64-linux-gnu

# Configure and build
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)
```

#### 32-bit on 64-bit
```bash
# Install 32-bit toolchain
sudo apt-get install gcc-multilib

# Build
make ARCH=i386 defconfig
make ARCH=i386 -j$(nproc)
```

### Using Different Compilers

#### Clang/LLVM
```bash
# Install clang
sudo apt-get install clang lld llvm

# Build with clang
make CC=clang LD=ld.lld defconfig
make CC=clang LD=ld.lld -j$(nproc)
```

#### Specific GCC Version
```bash
# Install specific version
sudo apt-get install gcc-11

# Build
make CC=gcc-11 defconfig
make CC=gcc-11 -j$(nproc)
```

### Out-of-Tree Builds
```bash
# Create build directory
mkdir ../build
cd ../build

# Configure and build
make -C ../linux O=$(pwd) defconfig
make -j$(nproc)
```

## 📦 Creating Packages

### Debian Packages
```bash
# Full package set
make -j$(nproc) deb-pkg

# Binaries only (faster)
make -j$(nproc) bindeb-pkg

# With custom version
make -j$(nproc) deb-pkg KDEB_PKGVERSION=$(date +%Y%m%d)
```

### RPM Packages
```bash
# Build RPMs
make -j$(nproc) rpm-pkg

# Binaries only
make -j$(nproc) binrpm-pkg

# With custom release
make -j$(nproc) rpm-pkg RPMOPTS="--define '_release $(date +%Y%m%d)'"
```

### Tarball
```bash
# Compressed with modules
make -j$(nproc) tar-pkg

# Installation tarball
make -j$(nproc) targz-pkg
```

## 🧪 Build Verification

### Check Config
```bash
# Verify security options
./scripts/check-hardening.sh

# Check for missing options
./scripts/kconfig/streamline_config.pl > config_check
```

### Test Build
```bash
# Boot test with QEMU
qemu-system-x86_64 \
  -kernel arch/x86/boot/bzImage \
  -append "console=ttyS0" \
  -nographic \
  -m 2G

# Run built-in tests
make kselftest
```

## ⚡ Build Optimization

### Speed Up Builds
```bash
# Use ccache
sudo apt-get install ccache
export PATH="/usr/lib/ccache:$PATH"

# Parallel jobs
make -j$(nproc)

# Skip unneeded drivers
make localmodconfig  # Only builds modules for current hardware
```

### Reduce Size
```bash
# Strip modules
make INSTALL_MOD_STRIP=1 modules_install

# Compress with XZ
./scripts/config --enable CONFIG_KERNEL_XZ
./scripts/config --enable CONFIG_MODULE_COMPRESS_XZ
```

## 🔧 Troubleshooting

### Common Issues

#### Missing Dependencies
```bash
# Check for missing packages
make menuconfig  # Will error if ncurses missing
make nconfig     # Alternative if menuconfig fails
```

#### Build Failures
```bash
# Clean and retry
make clean
make -j$(nproc)

# Or full clean
make mrproper
make defconfig
make -j$(nproc)
```

#### Out of Memory
```bash
# Reduce parallel jobs
make -j2

# Or increase swap
sudo dd if=/dev/zero of=/swapfile bs=1G count=4
sudo mkswap /swapfile
sudo swapon /swapfile
```

## 📊 Build Info

### Check Version
```bash
# Kernel version
make kernelversion

# Full version string
make kernelrelease

# Config details
scripts/config --state CONFIG_HARDENED_USERCOPY
```

### Build Statistics
```bash
# Time the build
time make -j$(nproc)

# Check size
du -sh .
size vmlinux
```

## 🚀 Installation

### Manual Install
```bash
# Install modules
sudo make modules_install

# Install kernel
sudo make install

# Update bootloader
sudo update-grub  # Debian/Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg  # Fedora
```

### Package Install
```bash
# Debian/Ubuntu
sudo dpkg -i ../linux-*.deb

# Fedora/RHEL
sudo rpm -i ~/rpmbuild/RPMS/x86_64/kernel-*.rpm
```

## 📚 Next Steps

- [[Custom-Builds]] - Advanced configurations
- [[Kernel-Debugging]] - Debug your build
- [[Performance-Tuning]] - Optimize for your use case
- [[Contributing]] - Submit your improvements

---

**Happy building! If you encounter issues, check our [FAQ](FAQ) or ask in [Discussions](https://github.com/einyx/linux/discussions). 🔨**