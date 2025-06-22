# Linux Community Kernel

A hardened Linux kernel fork with automated builds and security patches.

## Quick Start

**APT Repository** (Debian/Ubuntu):
```bash
# Add repository
wget -O - https://kain.example.com/kain-repo.asc | sudo apt-key add -
echo "deb https://kain.example.com stable main" | sudo tee /etc/apt/sources.list.d/kain.list
sudo apt update && sudo apt install linux-image-kain
```

**Direct Download**: [Latest Release](https://github.com/einyx/linux/releases/latest)

**Manual Install**:
```bash
# Debian/Ubuntu
wget -O kernel.deb [latest-release-url]
sudo dpkg -i kernel.deb

# Fedora/RHEL  
wget -O kernel.rpm [latest-release-url]
sudo rpm -i kernel.rpm
```

**Build from source**:
```bash
git clone https://github.com/einyx/linux.git
cd linux
make defconfig
make -j$(nproc)
```

## Documentation

**Basics**
- [[Getting Started]]
- [[Installation]]
- [[Building]]
- [[FAQ]]

**Security**
- [[Security Features]]
- [[Hardening Options]]
- [[Threat Model]]

**Development**
- [[Contributing]]
- [[Code Style]]
- [[Testing]]
- [[Debugging]]

**Advanced**
- [[Custom Configs]]
- [[Cross Compiling]]
- [[Performance]]
- [[Troubleshooting]]

## Features

- Security hardening inspired by grsecurity/PaX
- Automated CI/CD with multi-arch builds
- Pre-built packages for major distributions
- Regular security updates
- Community-driven development

## Status

- Build: ![Build Status](https://github.com/einyx/linux/workflows/Build%20DEB%20and%20RPM%20packages/badge.svg)
- Security: ![Security Scan](https://github.com/einyx/linux/workflows/Security%20Analysis/badge.svg)
- Tests: ![Test Status](https://github.com/einyx/linux/workflows/Kernel%20Testing/badge.svg)