# Building from Source

## Quick Build

```bash
git clone https://github.com/einyx/linux.git
cd linux
make defconfig
make -j$(nproc)
```

That's it for a basic build. For installation and customization, read on.

## Dependencies

**Debian/Ubuntu**:
```bash
sudo apt install build-essential bc kmod cpio flex bison libssl-dev libelf-dev git
# Optional: libncurses-dev (for menuconfig)
```

**Fedora/RHEL**:
```bash
sudo dnf install gcc make bc openssl-devel elfutils-libelf-devel bison flex git
# Optional: ncurses-devel
```

**Arch**:
```bash
sudo pacman -S base-devel bc kmod cpio flex bison openssl libelf git
# Optional: ncurses
```

## Configuration

### Use existing config
```bash
# Copy your current kernel's config
cp /boot/config-$(uname -r) .config
make olddefconfig
```

### Start fresh
```bash
make defconfig        # Sane defaults
make localmodconfig   # Only modules for current hardware
make tinyconfig      # Minimal kernel
```

### Customize
```bash
make menuconfig      # Terminal UI
make nconfig        # Newer terminal UI  
make xconfig        # Qt GUI (needs qt-devel)
make gconfig        # GTK GUI (needs gtk-devel)
```

### Security hardening
```bash
# Apply hardening options
./scripts/kconfig/merge_config.sh .config kernel/configs/hardening.config
make olddefconfig
```

## Building

### Standard build
```bash
make -j$(nproc)              # Use all CPU cores
make -j4                     # Use 4 cores
make                         # Single threaded
```

### Build targets
```bash
make vmlinux                 # Kernel image only
make modules                 # Modules only
make all                     # Everything (default)
make bzImage                 # Compressed kernel (x86)
make bindeb-pkg             # Debian packages
make binrpm-pkg             # RPM packages
```

### Cross compilation
```bash
# ARM64 on x86_64
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)

# 32-bit on 64-bit
make ARCH=i386 defconfig
make ARCH=i386 -j$(nproc)
```

### Alternative compilers
```bash
# Clang/LLVM
make CC=clang defconfig
make CC=clang -j$(nproc)

# Specific GCC version
make CC=gcc-11 -j$(nproc)
```

## Installation

### Manual install
```bash
sudo make modules_install
sudo make install

# Update bootloader
sudo update-grub                    # Debian/Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg  # Fedora
sudo grub-mkconfig -o /boot/grub/grub.cfg    # Arch
```

### Package install
```bash
# Build packages first
make -j$(nproc) bindeb-pkg          # Debian
make -j$(nproc) binrpm-pkg          # RPM

# Install
sudo dpkg -i ../linux-*.deb         # Debian
sudo rpm -i ~/rpmbuild/RPMS/*/kernel-*.rpm  # RPM
```

## Troubleshooting

### Build errors

**Missing dependency**:
```bash
# Check error message for missing file
# Install corresponding -dev/-devel package
```

**Out of memory**:
```bash
# Reduce parallel jobs
make -j2

# Add swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

**Config issues**:
```bash
# Start fresh
make mrproper
make defconfig
```

### Boot issues

**Kernel panic**:
- Boot previous kernel from GRUB
- Check `journalctl -b -1` for errors
- Disable problematic config option

**Missing modules**:
```bash
# Check which modules are needed
lsmod > needed_modules

# Rebuild with them
make localmodconfig
make -j$(nproc)
```

**Black screen**:
- Try `nomodeset` boot parameter
- Disable graphics drivers in config
- Use serial console for debugging

## Performance

### Speed up builds

**ccache**:
```bash
sudo apt install ccache
export PATH="/usr/lib/ccache:$PATH"
```

**Incremental builds**:
```bash
# Only rebuild changed files
make -j$(nproc)

# Force rebuild specific directory
touch drivers/gpu/drm/*
make -j$(nproc)
```

**Distributed builds**:
```bash
# Using distcc
sudo apt install distcc
export DISTCC_HOSTS="localhost/4 192.168.1.10/8"
make -j16 CC="distcc gcc"
```

### Reduce size

```bash
# Strip debug info
make INSTALL_MOD_STRIP=1 modules_install

# Compression
scripts/config --enable CONFIG_MODULE_COMPRESS_ZSTD
scripts/config --enable CONFIG_KERNEL_ZSTD
```

## Advanced

### Out-of-tree build
```bash
mkdir build
make O=build defconfig
make O=build -j$(nproc)
```

### Debug build
```bash
scripts/config --enable CONFIG_DEBUG_INFO
scripts/config --enable CONFIG_DEBUG_INFO_DWARF5
scripts/config --enable CONFIG_GDB_SCRIPTS
make -j$(nproc)
```

### Custom version string
```bash
# Edit .config
CONFIG_LOCALVERSION="-custom"

# Or via make
make LOCALVERSION=-custom -j$(nproc)
```

### Specific subsystem
```bash
# Build only one subsystem
make M=drivers/gpu/drm
make M=fs/ext4

# With verbose output
make V=1 M=net/ipv4
```

## Tips

- Save your working `.config` files
- Use `make help` to see all targets
- Read `Documentation/kbuild/` for details
- Enable only drivers you need
- Test in VM before real hardware
- Keep old kernels as fallback

## Next Steps

- [[Security Features]] - Enable hardening
- [[Testing]] - Verify your build
- [[Contributing]] - Submit improvements
- [[Custom Configs]] - Advanced configuration