# Quantum-Resistant Cryptography Module

## Overview

The Quantum-Resistant Cryptography module provides future-proof security against quantum computing threats by implementing post-quantum cryptographic algorithms alongside classical cryptography in a hybrid approach.

## Features

### 1. Post-Quantum Algorithms
- **CRYSTALS-Kyber**: Key encapsulation mechanism (KEM) for secure key exchange
  - Kyber768 (NIST Level 3 security)
  - Kyber1024 (NIST Level 5 security)
- **CRYSTALS-Dilithium**: Digital signature algorithm
  - Dilithium3 (NIST Level 3 security)
  - Dilithium5 (NIST Level 5 security)
- **FALCON**: Alternative signature scheme (planned)
- **SPHINCS+**: Hash-based signatures (planned)

### 2. Hybrid Cryptography
- Combines classical (AES-256) and post-quantum algorithms
- Provides security even if one algorithm is compromised
- Seamless fallback mechanisms

### 3. Key Management
- Automatic key generation and rotation
- Ephemeral key support for forward secrecy
- Configurable key lifetimes

### 4. Quantum-Secure Channels
- Establish secure communication channels between processes
- Authenticated key exchange using hybrid approach
- Perfect forward secrecy

### 5. Process Authentication
- Quantum-resistant digital signatures for process authentication
- Token-based authentication system
- Integration with existing LSM hooks

## Configuration

Enable quantum crypto in kernel config:
```
CONFIG_SECURITY_HARDENING_QUANTUM=y
```

## Usage

### Via SecurityFS

Status information:
```bash
cat /sys/kernel/security/hardening/quantum
```

Commands:
```bash
# Rotate quantum keys
echo "rotate" > /sys/kernel/security/hardening/quantum

# Authenticate current process
echo "authenticate" > /sys/kernel/security/hardening/quantum

# Establish quantum channel to another process
echo "channel <PID>" > /sys/kernel/security/hardening/quantum
```

### Security Levels

The module enforces quantum authentication for sensitive operations when security level is HIGH or CRITICAL:
- Access to files containing "secret", "private", "key", or "shadow"
- Inter-process communication in high-security contexts
- Cryptographic operations

## Performance Considerations

- Quantum algorithms have higher computational overhead than classical crypto
- Key generation is resource-intensive (performed asynchronously when possible)
- Hybrid approach balances security with performance

## Government/Military Applications

This module is specifically designed for high-security government and military deployments where:
- Long-term data protection is critical
- Quantum computing threats are a concern
- Compliance with post-quantum standards is required
- Defense against nation-state actors is necessary

## Future Enhancements

1. **Additional Algorithms**
   - NTRU for alternative lattice-based encryption
   - Classic McEliece for code-based cryptography
   - BIKE for more efficient key sizes

2. **Hardware Acceleration**
   - Integration with quantum-resistant crypto accelerators
   - FPGA offloading for lattice operations

3. **Standards Compliance**
   - FIPS 203/204/205 compliance when finalized
   - NSA Commercial National Security Algorithm Suite 2.0

4. **Advanced Features**
   - Quantum-safe TLS integration
   - Post-quantum PKI infrastructure
   - Quantum random number generation

## Security Considerations

- Keys and signatures are significantly larger than classical crypto
- Proper random number generation is critical
- Side-channel resistance is implemented but requires ongoing analysis
- Regular key rotation is enforced to limit exposure