# Getting Started

## What is this?

A community-maintained Linux kernel fork focused on security hardening and modern development practices. We provide:

- Pre-built kernel packages with security patches
- Automated testing and vulnerability scanning  
- Clear documentation for contributors
- Regular releases with the latest fixes

## Installation

### Pre-built packages

The easiest way to get started. Packages are built automatically for each commit.

**Debian/Ubuntu**:
```bash
# Download latest from releases page
wget https://github.com/einyx/linux/releases/latest/download/linux-image-VERSION-ARCH.deb
sudo dpkg -i linux-image-*.deb
sudo update-grub
sudo reboot
```

**Fedora/RHEL**:
```bash
wget https://github.com/einyx/linux/releases/latest/download/kernel-VERSION-ARCH.rpm
sudo rpm -i kernel-*.rpm
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
sudo reboot
```

**Arch Linux**:
```bash
# AUR package coming soon
# For now, build from source
```

### Build from source

If you need custom configuration or want to contribute.

**Dependencies**:
```bash
# Debian/Ubuntu
sudo apt install build-essential bc kmod cpio flex bison libssl-dev libelf-dev

# Fedora
sudo dnf install gcc make bc openssl-devel elfutils-libelf-devel bison flex

# Arch
sudo pacman -S base-devel bc kmod cpio flex bison openssl libelf
```

**Build**:
```bash
git clone https://github.com/einyx/linux.git
cd linux

# Use your current kernel config
cp /boot/config-$(uname -r) .config
make olddefconfig

# Or use defaults
make defconfig

# Build (adjust -j for your CPU count)
make -j8
sudo make modules_install
sudo make install
```

See [[Building]] for detailed instructions.

## Verify installation

After reboot:
```bash
uname -r  # Should show new kernel version
dmesg | grep "Linux version"  # Check boot messages
```

## Security features

This kernel includes hardening options enabled by default:

- KASLR (Kernel Address Space Layout Randomization)
- Stack protector
- Hardened usercopy
- Memory initialization
- Control flow integrity (on supported architectures)

Check enabled features:
```bash
grep CONFIG_HARDENED /boot/config-$(uname -r)
```

See [[Security Features]] for full details.

## Troubleshooting

**Boot issues**: 
- Hold Shift during boot to access GRUB menu
- Select previous kernel if new one fails
- Check `journalctl -b -1` for errors from failed boot

**Missing modules**:
```bash
# Rebuild with current config
make localmodconfig
make -j8 modules
sudo make modules_install
```

**Performance**: Some security features have overhead. See [[Performance]] for tuning.

## Next steps

- [[Security Features]] - Understand the hardening options
- [[Contributing]] - Help improve the kernel
- [[Building]] - Advanced build configurations
- [[FAQ]] - Common questions answered