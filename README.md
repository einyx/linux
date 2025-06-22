Linux kernel
============

There are several guides for kernel developers and users. These guides can
be rendered in a number of formats, like HTML and PDF. Please read
Documentation/admin-guide/README.rst first.

In order to build the documentation, use ``make htmldocs`` or
``make pdfdocs``.  The formatted documentation can also be read online at:

    https://www.kernel.org/doc/html/latest/

There are various text files in the Documentation/ subdirectory,
several of them using the reStructuredText markup notation.

Please read the Documentation/process/changes.rst file, as it contains the
requirements for building and running the kernel, and information about
the problems which may result by upgrading your kernel.
➜  staging git:(main) cat README.md
# Linux Kernel with Advanced Security Hardening Module

This is a fork of the Linux kernel that includes a security hardening module providing runtime protection against modern attack vectors through behavioral analysis and adaptive security controls.

## 🛡️ Security Features

### 1. **Behavioral Anomaly Detection**
- **ML-powered syscall analysis** using n-grams and Markov chains
- **Real-time exploitation detection** identifying unusual system call patterns
- **Zero-day protection** through behavioral analysis rather than signatures

### 2. **Temporal Access Control**
- **Time-based security policies** restricting operations to specific windows
- **Business hours enforcement** preventing after-hours unauthorized access
- **Maintenance window protection** with elevated security outside approved times

### 3. **Resource Usage Fingerprinting**
- **Cryptominer detection** through CPU/GPU usage pattern analysis
- **DoS attack prevention** by identifying resource exhaustion attempts
- **Process behavior baselining** with deviation alerts

### 4. **Container-Aware Security**
- **Container escape prevention** with namespace-aware controls
- **Docker/Kubernetes integration** for containerized workload protection
- **Per-container security policies** with different enforcement levels

### 5. **Adaptive Security Levels**
- **Dynamic threat response** escalating from NORMAL → ELEVATED → HIGH → CRITICAL
- **Automatic countermeasures** based on detected threat severity
- **Self-healing security posture** that adapts to attack patterns

### 6. **Memory Exploit Detection**
- **ROP/JOP chain detection** preventing code-reuse attacks
- **Heap spray prevention** blocking memory manipulation techniques
- **Stack pivot detection** identifying stack-based exploits
- **W^X enforcement monitoring** ensuring memory protection integrity

## 🚀 Quick Start

### Building the Kernel

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-hardened.git
cd linux-hardened

# Configure with hardening module enabled
make menuconfig
# Enable: Security options → Hardening Security Module

# Build the kernel
make -j$(nproc)
make modules_install
make install
```

### Testing in a VM

```bash
# Quick VM test with pre-built kernel
./test-hardening-vm.sh

# Inside the VM, run built-in tests
test-behavior    # Test anomaly detection
test-temporal    # Test time-based controls
test-resource    # Test resource monitoring
test-container   # Test container security
```

## 📊 Runtime Configuration

### Enable/Disable Module
```bash
echo 1 > /sys/kernel/security/hardening/enabled  # Enable
echo 0 > /sys/kernel/security/hardening/enabled  # Disable
```

### Set Enforcement Mode
```bash
echo 1 > /sys/kernel/security/hardening/enforce  # Block violations
echo 0 > /sys/kernel/security/hardening/enforce  # Monitor only
```

### View Statistics
```bash
cat /sys/kernel/security/hardening/stats
```

## 🔒 Attack Prevention Examples

### Prevents Exploitation Attempts
```bash
# Detected: Rapid syscall patterns indicating exploitation
# Action: Process termination or syscall blocking
```

### Prevents Cryptominers
```bash
# Detected: Sustained high CPU with specific instruction patterns
# Action: Process throttling or termination
```

### Prevents Container Escapes
```bash
# Detected: Namespace violation attempts
# Action: Container isolation enforcement
```

### Prevents Memory Corruption Exploits
```bash
# Detected: ROP gadget chains, heap sprays, stack pivots
# Action: Process termination and memory protection
```

## 📈 Performance Impact

- **Minimal overhead**: ~2-5% in normal operation
- **Adaptive algorithms**: Performance scales with threat level
- **Efficient caching**: Behavioral patterns cached for fast lookup
- **Configurable thresholds**: Tune sensitivity vs performance

## 🔧 Configuration Options

```bash
CONFIG_SECURITY_HARDENING=y          # Enable module
CONFIG_HARDENING_BEHAVIORAL=y        # Behavioral detection
CONFIG_HARDENING_TEMPORAL=y          # Time-based controls
CONFIG_HARDENING_RESOURCE=y          # Resource monitoring
CONFIG_HARDENING_CONTAINER=y         # Container security
CONFIG_HARDENING_MEMORY_PROTECT=y    # Memory exploit detection
```

## 📚 Documentation

- [Testing Guide](HARDENING_TEST_README.md) - Detailed testing instructions
- [Security Model](Documentation/security/hardening.txt) - Technical implementation details
- [API Reference](Documentation/ABI/testing/sysfs-kernel-security-hardening) - Sysfs interface documentation

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development

```bash
# Run test suite
./test-hardening-features.sh

# Check module logs
dmesg | grep hardening

# Debug mode
echo 1 > /sys/kernel/security/hardening/debug
```

## 📄 License

This project maintains the same license as the Linux kernel (GPLv2). See [COPYING](COPYING) for details.

## 🏆 Acknowledgments

Built upon the Linux kernel security subsystem with inspiration from:
- grsecurity/PaX for security hardening concepts
- RTKDSM for behavioral analysis approaches
- Modern EDR systems for adaptive security levels

## ⚠️ Disclaimer

This is an experimental security module. While it provides additional protection, it should be used as part of a comprehensive security strategy, not as a sole security measure.

---

**Note**: This module is under active development. Features and interfaces may change. Always test thoroughly before production deployment.%
