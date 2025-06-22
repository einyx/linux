# Quantum-Resistant Cryptography Module

## Overview

The Quantum-Resistant Cryptography module provides future-proof security against quantum computing threats by implementing NIST-approved post-quantum cryptographic algorithms alongside classical cryptography in a hybrid approach. This module is specifically designed for high-security government, military, and critical infrastructure deployments where long-term data protection against quantum threats is essential.

## Key Features

### Post-Quantum Algorithms

**CRYSTALS-Kyber (Key Encapsulation)**
- Kyber768: NIST Level 3 security (comparable to AES-192)
- Kyber1024: NIST Level 5 security (comparable to AES-256)
- Lattice-based cryptography resistant to Shor's algorithm
- Efficient key generation and encapsulation

**CRYSTALS-Dilithium (Digital Signatures)**
- Dilithium3: NIST Level 3 security
- Dilithium5: NIST Level 5 security
- Provides quantum-resistant authentication
- Larger signatures but proven security

### Hybrid Cryptography Approach

The module combines classical and post-quantum algorithms:
- **Key Exchange**: Kyber + ECDH/X25519
- **Encryption**: Post-quantum KEM + AES-256-GCM
- **Signatures**: Dilithium + Ed25519/RSA
- **Security**: Protected even if one algorithm fails

### Advanced Security Features

**Quantum-Secure Channels**
- Establish authenticated channels between processes
- Perfect forward secrecy with ephemeral keys
- Automatic key rotation based on time/usage
- Protection against quantum "harvest now, decrypt later" attacks

**Process Authentication**
- Quantum-resistant signatures for critical processes
- Token-based authentication system
- Integration with LSM (Linux Security Module) hooks
- Prevents quantum-powered impersonation attacks

**Key Management**
- Automatic key generation using kernel RNG
- Configurable key lifetimes (default: 24 hours)
- Secure key storage in kernel memory
- Emergency key rotation capabilities

## Configuration

### Kernel Configuration

Enable in menuconfig:
```
Security options --->
  [*] Security Hardening --->
    [*] Quantum-Resistant Cryptography (CONFIG_SECURITY_HARDENING_QUANTUM)
      [*] Use Kyber768 (Level 3) (CONFIG_QUANTUM_KYBER768)
      [ ] Use Kyber1024 (Level 5) (CONFIG_QUANTUM_KYBER1024)
      [*] Use Dilithium3 (Level 3) (CONFIG_QUANTUM_DILITHIUM3)
      [ ] Use Dilithium5 (Level 5) (CONFIG_QUANTUM_DILITHIUM5)
```

### Runtime Configuration

Via SecurityFS interface:
```bash
# Check quantum crypto status
cat /sys/kernel/security/hardening/quantum

# Example output:
quantum_crypto: enabled
kyber_level: 768 (NIST Level 3)
dilithium_level: 3 (NIST Level 3)
keys_generated: 42
signatures_created: 156
channels_active: 3
last_rotation: 2024-12-22 10:30:00
```

### Security Levels Integration

The quantum module integrates with the hardening LSM security levels:

| Level | Quantum Features |
|-------|-----------------|
| LOW | Disabled |
| MEDIUM | Optional authentication |
| HIGH | Required for sensitive files |
| CRITICAL | Required for all IPC |
| PARANOID | Maximum key sizes, frequent rotation |

## Usage Examples

### Manual Key Rotation
```bash
# Force immediate key rotation
echo "rotate" > /sys/kernel/security/hardening/quantum
```

### Process Authentication
```bash
# Authenticate current process with quantum signature
echo "authenticate" > /sys/kernel/security/hardening/quantum
```

### Quantum Channel Creation
```bash
# Create quantum-secure channel to PID 1234
echo "channel 1234" > /sys/kernel/security/hardening/quantum
```

### Monitoring
```bash
# View quantum crypto statistics
cat /proc/hardening/quantum_stats

# Example output:
Quantum Cryptography Statistics:
================================
Kyber Operations:
  Key Generation: 42 (avg 125ms)
  Encapsulations: 1,523 (avg 2.1ms)
  Decapsulations: 1,520 (avg 2.3ms)

Dilithium Operations:
  Key Generation: 15 (avg 89ms)
  Signatures: 156 (avg 4.5ms)
  Verifications: 423 (avg 3.2ms)

Performance Impact:
  CPU Overhead: 2.3%
  Memory Usage: 12MB
  Active Channels: 3
```

## Performance Considerations

### Overhead Comparison

| Operation | Classical | Post-Quantum | Hybrid |
|-----------|-----------|--------------|--------|
| Key Gen | 1ms | 100-150ms | 150ms |
| Key Exchange | 0.5ms | 2-3ms | 3.5ms |
| Sign | 0.1ms | 4-5ms | 5ms |
| Verify | 0.05ms | 3-4ms | 4ms |

### Optimization Tips

1. **Use appropriate security levels**
   - Level 3 for most applications
   - Level 5 only for ultra-high security

2. **Batch operations**
   - Group signature operations
   - Reuse quantum channels

3. **Configure key rotation**
   - Balance security vs performance
   - Longer lifetimes for stable systems

4. **Hardware acceleration**
   - Enable AES-NI for hybrid crypto
   - Future: Quantum crypto accelerators

## Use Cases

### Government/Military
- Classified communications
- Long-term document protection
- Critical infrastructure control
- Defense against nation-state quantum threats

### Financial Services
- Transaction authentication
- Long-term record protection
- Regulatory compliance (quantum-ready)

### Healthcare
- Patient record encryption
- Medical device authentication
- HIPAA compliance enhancement

### Critical Infrastructure
- SCADA system protection
- Power grid security
- Transportation systems

## Implementation Details

### Algorithm Parameters

**Kyber768**
- Polynomial degree: n = 256
- Module rank: k = 3
- Modulus: q = 3329
- Security: ~180-bit classical, quantum-resistant

**Dilithium3**
- Modulus: q = 8380417
- Dimensions: (k,l) = (6,5)
- Signature size: ~3.3KB
- Public key: ~1.9KB

### Memory Layout

The module maintains per-process quantum contexts:
```c
struct hardening_quantum_ctx {
    void *kyber_sk;      // Secret key
    void *kyber_pk;      // Public key
    void *dilithium_sk;  // Signing key
    void *dilithium_pk;  // Verification key
    u64 key_generation_time;
    u64 usage_count;
    struct list_head channels;
};
```

### Integration Points

1. **LSM Hooks**
   - file_open: Enforce quantum auth for sensitive files
   - task_create: Initialize quantum context
   - ipc_permission: Quantum channel requirements

2. **Crypto API**
   - Registers as crypto_alg providers
   - Transparent fallback to classical

3. **Audit System**
   - Logs all quantum operations
   - Tracks authentication failures

## Security Analysis

### Threat Model

**Protects Against:**
- Quantum computers running Shor's algorithm
- Store-now-decrypt-later attacks
- Quantum-enhanced cryptanalysis
- Side-channel attacks (implementation hardened)

**Assumptions:**
- Proper random number generation
- Secure key storage
- Protected kernel memory
- Trusted boot chain

### Known Limitations

1. **Performance Impact**
   - Higher CPU usage than classical crypto
   - Larger key/signature sizes
   - Initial key generation latency

2. **Compatibility**
   - Not all applications quantum-aware
   - Larger network packets
   - Storage overhead

3. **Maturity**
   - Algorithms recently standardized
   - Ongoing cryptanalysis
   - Implementation refinements needed

## Future Roadmap

### Planned Algorithms
- **FALCON**: Faster signatures
- **SPHINCS+**: Hash-based signatures
- **Classic McEliece**: Code-based KEM
- **NTRU**: Alternative lattice-based

### Hardware Support
- Quantum crypto accelerators
- FPGA implementations
- Dedicated ASIC support

### Standards Compliance
- FIPS 203/204/205 certification
- Common Criteria evaluation
- NSA CNSA 2.0 compliance

### Advanced Features
- Quantum key distribution (QKD) integration
- Post-quantum TLS/IPSec
- Quantum-safe PKI infrastructure
- Zero-knowledge proofs

## Troubleshooting

### Common Issues

**High CPU usage**
- Check security level settings
- Reduce key rotation frequency
- Use Level 3 instead of Level 5

**Authentication failures**
- Verify quantum module loaded
- Check process has quantum context
- Review audit logs

**Performance degradation**
- Monitor /proc/hardening/quantum_stats
- Adjust algorithm parameters
- Consider classical fallback

### Debug Options

```bash
# Enable verbose logging
echo 1 > /sys/kernel/debug/quantum_crypto/debug

# Dump quantum contexts
cat /sys/kernel/debug/quantum_crypto/contexts

# Force garbage collection
echo "gc" > /sys/kernel/security/hardening/quantum
```

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
- [Quantum Threat Timeline](https://globalriskinstitute.org/quantum-threat-timeline/)

## Related Documentation

- [[Security-Features]] - Overview of all security features
- [[Security-Hardening-LSM-Guide]] - Integration with hardening LSM
- [[Building]] - Compilation with quantum support