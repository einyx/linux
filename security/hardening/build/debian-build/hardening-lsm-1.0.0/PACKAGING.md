# Security Hardening LSM - Package Distribution Guide

This guide covers building and distributing packages for the Security Hardening LSM across different Linux distributions.

## Package Types Available

### 1. Debian/Ubuntu (.deb)
- **Package**: `hardening-lsm-dkms` - Main DKMS module
- **Package**: `hardening-lsm-tools` - Management tools
- **Package**: `hardening-lsm-doc` - Documentation
- **Build**: `dpkg-buildpackage -us -uc`
- **Install**: `sudo dpkg -i hardening-lsm*.deb`

### 2. Red Hat/Fedora/CentOS (.rpm)
- **Package**: `hardening-lsm` - Main module with DKMS
- **Package**: `hardening-lsm-tools` - Management tools
- **Package**: `hardening-lsm-doc` - Documentation
- **Build**: `rpmbuild -ba packaging/rpm/hardening-lsm.spec`
- **Install**: `sudo rpm -ivh hardening-lsm*.rpm`

### 3. Arch Linux (.pkg.tar.zst)
- **Package**: `hardening-lsm` - Main module
- **Package**: `hardening-lsm-tools` - Management tools
- **Package**: `hardening-lsm-docs` - Documentation
- **Build**: `makepkg -s`
- **Install**: `sudo pacman -U hardening-lsm*.pkg.tar.zst`

### 4. Gentoo (.ebuild)
- **Package**: `sys-kernel/hardening-lsm`
- **Build**: `emerge hardening-lsm`
- **Install**: Automatic via Portage

### 5. DKMS (Universal)
- **Package**: Source distribution with DKMS support
- **Install**: `sudo ./install.sh`
- **Works**: On any distribution with DKMS support

## Building All Packages

### Automated Build
```bash
cd packaging
./build-packages.sh
```

This script will:
- Detect available build tools
- Build packages for supported distributions
- Create source distributions
- Generate checksums

### Manual Building

#### Debian Package
```bash
# Install build dependencies
sudo apt-get install debhelper dkms linux-headers-generic

# Build package
dpkg-buildpackage -us -uc

# Install
sudo dpkg -i ../hardening-lsm*.deb
sudo apt-get install -f  # Fix dependencies
```

#### RPM Package
```bash
# Install build dependencies
sudo dnf install rpm-build dkms kernel-devel

# Build package
rpmbuild --define "_topdir $(pwd)/rpm-build" \
         -ba packaging/rpm/hardening-lsm.spec

# Install
sudo rpm -ivh rpm-build/RPMS/*/hardening-lsm*.rpm
```

#### Arch Package
```bash
# Install build dependencies
sudo pacman -S base-devel

# Build package
cd packaging/arch
makepkg -s

# Install
sudo pacman -U hardening-lsm*.pkg.tar.zst
```

## Installation Methods

### Method 1: Distribution Packages
Use the appropriate package for your distribution (recommended).

### Method 2: Universal Installer
```bash
sudo ./install.sh
```

### Method 3: Manual DKMS
```bash
# Copy source
sudo cp -r . /usr/src/hardening-lsm-1.0.0/

# Add to DKMS
sudo dkms add -m hardening-lsm -v 1.0.0

# Build and install
sudo dkms build -m hardening-lsm -v 1.0.0
sudo dkms install -m hardening-lsm -v 1.0.0
```

## Package Contents

### Main Module Package
- DKMS source code
- Kernel module build configuration
- Module installation scripts
- Boot loader configuration updates

### Tools Package
- `hardening-ctl` - Main control utility
- `hardening-status` - Status display tool
- `hardening-profiles` - Profile management
- SystemD service files
- Configuration directories

### Documentation Package
- README and installation guide
- API documentation
- Example configurations
- Security profile templates

## Configuration

### Boot Loader Setup
The module requires adding `hardening` to the kernel LSM list:

```bash
# GRUB (most distributions)
GRUB_CMDLINE_LINUX_DEFAULT="... lsm=landlock,lockdown,yama,loadpin,safesetid,hardening,selinux,apparmor"

# Update GRUB
sudo update-grub  # Debian/Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg  # RHEL/Fedora
```

### Runtime Configuration
```bash
# Enable module
sudo hardening-ctl enable

# Set enforcement mode
sudo hardening-ctl enforce

# Check status
hardening-status

# Apply security profile
sudo hardening-ctl profile web-server
```

## Distribution-Specific Notes

### Ubuntu/Debian
- Uses `dkms` for automatic kernel module rebuilding
- Integrates with `apt` dependency system
- Automatic GRUB configuration updates

### RHEL/Fedora/CentOS
- Uses `dkms` for kernel module management
- Integrates with `yum`/`dnf` package managers
- SELinux compatibility ensured

### Arch Linux
- Follows Arch packaging guidelines
- Uses `PKGBUILD` with proper dependencies
- Automatic kernel hook integration

### Gentoo
- Source-based installation via Portage
- USE flags for optional features
- Automatic kernel configuration

## Repository Setup

### APT Repository (Debian/Ubuntu)
```bash
# Add repository key
wget -qO - https://repo.hardening-lsm.org/gpg.key | sudo apt-key add -

# Add repository
echo "deb https://repo.hardening-lsm.org/apt stable main" | \
    sudo tee /etc/apt/sources.list.d/hardening-lsm.list

# Install
sudo apt update
sudo apt install hardening-lsm-dkms hardening-lsm-tools
```

### YUM/DNF Repository (RHEL/Fedora)
```bash
# Add repository
sudo tee /etc/yum.repos.d/hardening-lsm.repo << EOF
[hardening-lsm]
name=Security Hardening LSM
baseurl=https://repo.hardening-lsm.org/rpm/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://repo.hardening-lsm.org/gpg.key
EOF

# Install
sudo dnf install hardening-lsm hardening-lsm-tools
```

### AUR (Arch Linux)
```bash
# Install from AUR
yay -S hardening-lsm

# Or manually
git clone https://aur.archlinux.org/hardening-lsm.git
cd hardening-lsm
makepkg -si
```

## Testing Packages

### Package Testing Script
```bash
# Test installation
sudo ./test-package.sh debian  # or rpm, arch

# Verify functionality
hardening-status
sudo hardening-ctl status
```

### Continuous Integration
- Automated building for multiple distributions
- Package testing in clean environments
- Installation verification
- Functionality testing

## Troubleshooting

### Common Issues
1. **Kernel headers missing**: Install appropriate kernel headers package
2. **DKMS build failure**: Ensure build tools are installed
3. **Module not loading**: Check kernel LSM configuration
4. **Permission denied**: Ensure running with appropriate privileges

### Debug Information
```bash
# Check DKMS status
sudo dkms status

# Check module loading
sudo modinfo hardening

# Check kernel logs
sudo dmesg | grep hardening

# Verify LSM integration
cat /sys/kernel/security/lsm
```

## Contributing Packages

### Adding New Distribution Support
1. Create packaging files in `packaging/<distro>/`
2. Update `build-packages.sh`
3. Add installation instructions
4. Test package installation and functionality

### Package Maintenance
- Monitor distribution-specific packaging guidelines
- Update dependencies as needed
- Ensure compatibility with new kernel versions
- Maintain package metadata accuracy