# Security Features

This kernel implements defense-in-depth security hardening inspired by grsecurity, KSPP, and modern research.

## Enabled by Default

### Memory Protection

**CONFIG_HARDENED_USERCOPY=y**
- Bounds checking on copy_to_user()/copy_from_user()
- Prevents buffer overflows in user/kernel data transfers
- ~1-3% performance impact

**CONFIG_FORTIFY_SOURCE=y**
- Compile-time and runtime buffer overflow detection
- Replaces unsafe string functions with bounds-checked versions
- Minimal performance impact

**CONFIG_STACKPROTECTOR_STRONG=y**
- Stack canaries to detect buffer overflows
- Compiler inserts checks in functions with stack buffers
- ~1-2% performance overhead

**CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y**
- Zero memory on allocation
- Prevents information leaks
- ~3-5% overhead (can be disabled with init_on_alloc=0)

### Address Space Protection

**CONFIG_RANDOMIZE_BASE=y (KASLR)**
- Randomizes kernel load address
- Makes ROP/JOP attacks harder
- No performance impact

**CONFIG_RANDOMIZE_MEMORY=y**
- Randomizes physical memory regions
- Defeats hardcoded address attacks
- No performance impact

**CONFIG_STRICT_KERNEL_RWX=y**
- Write-protect kernel code, read-only data
- Prevents code modification attacks
- No runtime overhead

### Exploit Mitigation

**CONFIG_PAGE_TABLE_ISOLATION=y**
- Mitigates Meltdown (CVE-2017-5754)
- Separate page tables for kernel/user
- ~5-30% overhead depending on workload

**CONFIG_RETPOLINE=y**
- Mitigates Spectre v2 (CVE-2017-5715)
- Indirect branch protection
- ~0-10% overhead

**CONFIG_SLS=y**
- Straight-line speculation mitigation
- Prevents speculative execution attacks
- Minimal overhead

## Optional Hardening

Can be enabled via menuconfig or kernel parameters:

### Sanitizers (Debug/Testing)

**CONFIG_KASAN=y**
- Dynamic memory error detector
- Finds use-after-free, out-of-bounds
- 3x memory overhead, 2-3x CPU overhead
- Enable only for testing

**CONFIG_KCSAN=y**
- Data race detector
- Finds concurrency bugs
- Significant overhead
- Testing only

### Additional Mitigations

**CONFIG_CFI_CLANG=y**
- Control Flow Integrity
- Prevents code-reuse attacks
- ~3-5% overhead
- Requires Clang compiler

**CONFIG_SHADOW_CALL_STACK=y**
- Separate shadow stack (ARM64 only)
- Prevents ROP attacks
- ~1% overhead

**CONFIG_ZERO_CALL_USED_REGS=y**
- Clear registers on function return
- Reduces ROP gadgets
- ~1% overhead

## Configuration

### Maximum Security

```bash
# Apply all hardening options
make defconfig
./scripts/kconfig/merge_config.sh .config \
    kernel/configs/hardening.config \
    kernel/configs/x86_64_defconfig

# Additional options
scripts/config --enable CONFIG_INIT_ON_FREE_DEFAULT_ON
scripts/config --enable CONFIG_SLAB_FREELIST_RANDOM
scripts/config --enable CONFIG_SHUFFLE_PAGE_ALLOCATOR
scripts/config --enable CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT

make olddefconfig
```

### Performance-Sensitive

```bash
# Disable expensive mitigations
scripts/config --disable CONFIG_PAGE_TABLE_ISOLATION
scripts/config --disable CONFIG_INIT_ON_ALLOC_DEFAULT_ON
scripts/config --set-str CONFIG_INIT_ON_ALLOC_DEFAULT_ON ""
```

### Runtime Tuning

Boot parameters:
```
# Disable mitigations (unsafe!)
mitigations=off

# Selective disable
init_on_alloc=0
init_on_free=0
pti=off
spectre_v2=off

# Enable additional hardening
slub_debug=FZ
```

## Verification

Check active mitigations:
```bash
# Compile-time features
grep CONFIG_HARDENED /boot/config-$(uname -r)

# Runtime status
cat /sys/devices/system/cpu/vulnerabilities/*
dmesg | grep -i "protection\|hardened"

# Memory protections
sudo cat /proc/sys/kernel/randomize_va_space  # Should be 2
```

## Performance Impact

Typical overhead with default hardening:

| Workload | Overhead |
|----------|----------|
| Kernel compile | 3-5% |
| Web server | 5-10% |
| Database | 10-15% |
| Gaming | 2-5% |
| Desktop use | 1-3% |

Biggest impacts:
- PTI (Page Table Isolation): syscall-heavy workloads
- Init-on-alloc: memory intensive applications
- FORTIFY_SOURCE: negligible

## Custom Security Modules

### Hardening LSM

A comprehensive Linux Security Module providing innovative security features:

**Container Security**
- Automatic Docker/container detection
- Container escape prevention
- Docker socket protection
- Per-container security policies
- Network isolation enforcement

**Advanced Features**
- ML-inspired behavioral anomaly detection
- Temporal access control (time-based policies)
- Resource usage fingerprinting
- Process lineage tracking
- Memory access pattern analysis

**Performance Optimizations**
- RCU-based policy lookups
- Per-CPU statistics
- Batched syscall analysis
- Fast-path for common operations

See [[Security Hardening LSM Guide]] and [[Docker Container Security]] for details.

### Quantum-Resistant Cryptography

**Post-Quantum Protection**
- CRYSTALS-Kyber key encapsulation (NIST approved)
- CRYSTALS-Dilithium digital signatures
- Hybrid classical/quantum cryptography
- Protection against "harvest now, decrypt later" attacks

**Quantum Security Features**
- Quantum-secure inter-process channels
- Post-quantum authentication for sensitive operations
- Automatic key rotation with forward secrecy
- Integration with security level policies

See [[Quantum-Resistant-Cryptography]] for complete documentation.

### Anti-Malware Protection

**Real-time Malware Detection**
- Ransomware behavior blocking
- Cryptominer detection and prevention
- Suspicious execution pattern analysis
- Fileless malware prevention

**Behavioral Detection**
- File operation pattern analysis
- Process lineage tracking
- Entropy-based encryption detection
- Execution path restrictions

See [[Anti-Malware-Protection]] for complete documentation.

## Threat Model

Protects against:
- Memory corruption (buffer overflows, UAF)
- Information leaks
- Code injection
- ROP/JOP attacks  
- Speculative execution attacks
- Privilege escalation
- Container escapes
- Docker API abuse

Does NOT protect against:
- Hardware vulnerabilities (Rowhammer, etc)
- Malicious kernel modules
- Physical access attacks
- Zero-day exploits in enabled code

## Comparison with Stock Kernel

| Feature | Stock | Ours | grsecurity |
|---------|-------|------|------------|
| KASLR | Optional | Default | Enhanced |
| Stack protector | Weak | Strong | Strong |
| Hardened usercopy | No | Yes | Yes |
| FORTIFY_SOURCE | Partial | Full | Full |
| Memory init | No | Yes | Yes |
| CFI | No | Optional | Yes |

## Further Reading

- [KSPP Recommended Settings](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings)
- [Linux Kernel Defense Map](https://github.com/a13xp0p0v/linux-kernel-defence-map)
- [Kernel Hardening Checker](https://github.com/a13xp0p0v/kconfig-hardened-check)