# Getting Started

Welcome to the Community Linux Kernel! This guide will help you get up and running quickly.

## 🎯 Choose Your Path

### 🚀 Path 1: Use Pre-Built Packages (Easiest)

Perfect if you want to:
- Try the security-hardened kernel quickly
- Deploy to production systems
- Test without building

**[→ Go to Installation Guide](Installation)**

### 🔧 Path 2: Build From Source

Ideal if you want to:
- Customize kernel configuration
- Contribute to development
- Learn kernel internals

**[→ Go to Build Instructions](Building-from-Source)**

### 👥 Path 3: Contribute

Great if you want to:
- Fix bugs or add features
- Improve security
- Join the community

**[→ Go to Contributing Guide](Contributing)**

## 📋 Prerequisites

### For Using Pre-Built Packages
- Linux system (Debian/Ubuntu or Fedora/RHEL based)
- Root/sudo access
- 100MB free space

### For Building From Source
- Linux development system
- 25GB free disk space
- 4GB+ RAM (8GB recommended)
- Basic command line knowledge

### For Contributing
- Git knowledge
- C programming basics
- GitHub account
- Development environment

## 🚦 Quick Start Commands

### Option 1: Install Latest Release
```bash
# For Debian/Ubuntu
wget https://github.com/einyx/linux/releases/latest/download/linux-image-amd64.deb
sudo dpkg -i linux-image-amd64.deb

# For Fedora/RHEL
wget https://github.com/einyx/linux/releases/latest/download/kernel-x86_64.rpm
sudo rpm -i kernel-x86_64.rpm
```

### Option 2: Clone and Build
```bash
# Clone repository
git clone https://github.com/einyx/linux.git
cd linux

# Quick build with security hardening
make defconfig
./scripts/kconfig/merge_config.sh .config kernel/configs/hardening.config
make -j$(nproc)
```

### Option 3: Create First PR
```bash
# Fork on GitHub first, then:
git clone https://github.com/YOUR_USERNAME/linux.git
cd linux
git checkout -b my-first-fix

# Make changes, then:
git add -A
git commit -s -m "fix: correct typo in documentation"
git push origin my-first-fix
# Create PR on GitHub
```

## 🎓 Learning Resources

### Kernel Basics
- [[Kernel-Architecture]] - Understanding kernel structure
- [[Security-Features]] - Our security enhancements
- [[Development-Workflow]] - How we work

### Video Tutorials
- 🎥 [Installing Pre-Built Packages](https://example.com)
- 🎥 [Your First Kernel Build](https://example.com)
- 🎥 [Making Your First Contribution](https://example.com)

### Community Resources
- 💬 [Discord Server](https://discord.gg/example)
- 📧 [Mailing List](mailto:kernel@example.com)
- 🐦 [Twitter Updates](https://twitter.com/example)

## 🔍 Understanding Our Kernel

### Key Differences
Our kernel differs from vanilla Linux by:

1. **Security Hardening**
   - Memory protection enhancements
   - Additional runtime checks
   - Hardened defaults

2. **Community Focus**
   - Easier contribution process
   - Better documentation
   - Welcoming environment

3. **Modern CI/CD**
   - Automated testing
   - Security scanning
   - Package building

### Version Scheme
```
v6.16.0-20240322-a1b2c3d4
   │      │         │
   │      │         └── Git commit (short)
   │      └──────────── Build date
   └──────────────────── Kernel version
```

## ⚡ Quick Tips

### Performance
- Use pre-built packages for production
- Custom builds can enable specific optimizations
- Security features may have minor performance impact

### Security
- All builds include hardening by default
- Check [[Security-Configuration]] for maximum protection
- Regular updates recommended

### Troubleshooting
- Check [[FAQ]] for common issues
- Search existing [Issues](https://github.com/einyx/linux/issues)
- Ask in [Discussions](https://github.com/einyx/linux/discussions)

## 🎯 Next Steps

Based on your goals:

1. **Just want to use it?**
   - [[Installation]] - Install packages
   - [[Security-Configuration]] - Optimize security

2. **Want to build?**
   - [[Building-from-Source]] - Detailed build guide
   - [[Custom-Builds]] - Advanced configurations

3. **Want to contribute?**
   - [[First-Contribution]] - Step-by-step guide
   - [[Development-Workflow]] - Our processes

## 🆘 Getting Help

- **Documentation**: You're here! 📚
- **Issues**: [GitHub Issues](https://github.com/einyx/linux/issues)
- **Discussions**: [GitHub Discussions](https://github.com/einyx/linux/discussions)
- **Security**: [Security Advisories](https://github.com/einyx/linux/security/advisories)

---

**Welcome to the community! We're excited to have you here. 🎉**