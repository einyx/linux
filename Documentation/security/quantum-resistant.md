# Quantum-Resistant Cryptography Module

## Overview

The Linux kernel's quantum-resistant cryptography module provides post-quantum security features to protect against future quantum computing threats. This module implements NIST-standardized post-quantum algorithms and provides a hybrid approach combining classical and quantum-resistant cryptography.

## Features

### 1. Post-Quantum Key Encapsulation (KEM)
- **CRYSTALS-Kyber**: Lattice-based KEM
  - Kyber768 (NIST Level 3 security)
  - Kyber1024 (NIST Level 5 security)

### 2. Post-Quantum Digital Signatures
- **CRYSTALS-Dilithium**: Lattice-based signatures
  - Dilithium3 (NIST Level 3)
  - Dilithium5 (NIST Level 5)

### 3. Hybrid Cryptography
- Combines classical (RSA/ECC) with post-quantum algorithms
- Provides security against both classical and quantum attacks
- Automatic fallback mechanisms

### 4. Quantum-Secure Channels
- Process-to-process quantum-secure communication
- Automatic key rotation based on time/usage
- Perfect forward secrecy with ephemeral keys

## Configuration

Enable the following kernel options:

```
CONFIG_SECURITY=y
CONFIG_SECURITY_HARDENING=y
CONFIG_SECURITY_HARDENING_QUANTUM=y
CONFIG_CRYPTO_SHA3=y
```

## Usage

### 1. Mount Security Filesystem

```bash
mount -t securityfs none /sys/kernel/security
```

### 2. Check Module Status

```bash
cat /sys/kernel/security/hardening/quantum/enabled
cat /sys/kernel/security/hardening/quantum/algorithms
```

### 3. Using from Userspace

The module exposes the following interfaces via securityfs:

- `/sys/kernel/security/hardening/quantum/enabled` - Module status
- `/sys/kernel/security/hardening/quantum/kem_algorithm` - Current KEM algorithm
- `/sys/kernel/security/hardening/quantum/signature_algorithm` - Current signature algorithm
- `/sys/kernel/security/hardening/quantum/create_channel` - Create quantum channel
- `/sys/kernel/security/hardening/quantum/generate_key` - Generate keypair
- `/sys/kernel/security/hardening/quantum/stats` - Statistics

### 4. Example Code

```c
/* Create a quantum-secure channel */
int fd = open("/sys/kernel/security/hardening/quantum/create_channel", O_WRONLY);
write(fd, "1", 1);
close(fd);

/* Generate quantum-resistant keypair */
fd = open("/sys/kernel/security/hardening/quantum/generate_key", O_WRONLY);
write(fd, "kyber768", 8);
close(fd);
```

## Performance Considerations

1. **Key Generation**: ~1-5ms for Kyber768
2. **Encapsulation**: ~0.5-1ms
3. **Decapsulation**: ~0.5-1ms
4. **Signature Generation**: ~2-5ms for Dilithium3
5. **Signature Verification**: ~1-2ms

## Security Levels

| Algorithm | NIST Level | Classical Security | Use Case |
|-----------|------------|-------------------|----------|
| Kyber768 | 3 | ~AES-192 | General purpose |
| Kyber1024 | 5 | ~AES-256 | High security |
| Dilithium3 | 3 | ~AES-192 | Standard signatures |
| Dilithium5 | 5 | ~AES-256 | Critical signatures |

## Best Practices

1. **Use Hybrid Mode**: Always enable hybrid cryptography for defense in depth
2. **Key Rotation**: Configure automatic key rotation (default: 24 hours)
3. **Monitor Performance**: Use the stats interface to monitor overhead
4. **Algorithm Selection**: Choose based on security requirements vs performance

## Limitations

1. **Increased Key Sizes**: Post-quantum keys are larger than classical
2. **Performance Overhead**: ~10-20% overhead compared to classical crypto
3. **Compatibility**: May not interoperate with systems lacking PQC support

## Future Enhancements

1. Integration with kernel crypto API
2. Hardware acceleration support
3. Additional NIST PQC winners (SPHINCS+, Falcon)
4. Network protocol integration (IPsec, WireGuard)

## Testing

Use the provided test tools:

```bash
# Run basic tests
./test-quantum.sh

# Run performance benchmarks
./quantum-test
```

## References

1. [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
2. [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
3. [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)

## Debugging

Enable debug output:

```bash
echo 1 > /sys/kernel/security/hardening/quantum/debug
dmesg | grep quantum
```

## Support

Report issues to the Linux kernel security mailing list with "[PQC]" prefix.