# Integrating liboqs into Linux Kernel Quantum Module

## Overview

liboqs (Open Quantum Safe) is a C library providing quantum-resistant cryptographic algorithms. This guide explains how to integrate liboqs into the Linux kernel's quantum-resistant security module.

## Challenges

Integrating liboqs into the kernel requires addressing:
1. **Kernel space restrictions** - No standard C library, limited stack
2. **Memory management** - Must use kernel allocators (kmalloc/kfree)
3. **No floating point** - Kernel doesn't allow FPU operations
4. **Security** - Constant-time operations, no data leaks

## Integration Approach

### 1. Kernel-Compatible liboqs Port

Create a minimal kernel-space version of liboqs:

```
security/hardening/liboqs-kernel/
├── include/
│   ├── oqs.h              # Main API header
│   ├── common.h           # Common definitions
│   └── kem/               # KEM algorithms
│       ├── kyber/
│       └── api.h
├── kem/
│   ├── kyber/
│   │   ├── kyber768.c
│   │   └── kyber1024.c
│   └── kem.c
├── sig/
│   ├── dilithium/
│   │   ├── dilithium3.c
│   │   └── dilithium5.c
│   └── sig.c
└── common/
    ├── rand.c             # Kernel RNG interface
    └── sha3.c             # Use kernel's SHA3
```

### 2. Memory Management Wrapper

```c
/* Kernel memory allocation wrapper for liboqs */
#define OQS_MEM_malloc(size)       kmalloc(size, GFP_KERNEL)
#define OQS_MEM_free(ptr)          kfree(ptr)
#define OQS_MEM_calloc(num, size)  kcalloc(num, size, GFP_KERNEL)
#define OQS_MEM_realloc(ptr, size) krealloc(ptr, size, GFP_KERNEL)
```

### 3. Random Number Generation

```c
/* Use kernel's cryptographically secure RNG */
void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read) {
    get_random_bytes(random_array, bytes_to_read);
}
```

### 4. Integration Steps

#### Step 1: Download liboqs
```bash
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
```

#### Step 2: Extract Required Files
Extract only the algorithms we need:
- Kyber (KEM)
- Dilithium (Signatures)
- Common utilities

#### Step 3: Kernel Adaptation Script
```bash
#!/bin/bash
# adapt-liboqs-kernel.sh
# Adapts liboqs code for kernel use

# Remove stdlib dependencies
sed -i 's/#include <stdlib.h>/\/\/#include <stdlib.h>/' *.c
sed -i 's/#include <string.h>/\/\/#include <string.h>/' *.c

# Replace memory functions
sed -i 's/malloc(/OQS_MEM_malloc(/' *.c
sed -i 's/free(/OQS_MEM_free(/' *.c
sed -i 's/calloc(/OQS_MEM_calloc(/' *.c

# Replace string functions with kernel equivalents
sed -i 's/memcpy(/crypto_memcpy(/' *.c
sed -i 's/memset(/crypto_memzero(/' *.c
```

### 5. Kernel Module Integration

Update `security/hardening/quantum.c`:

```c
#include "liboqs-kernel/include/oqs.h"

/* Initialize liboqs Kyber */
static int init_kyber(struct hardening_quantum_ctx *ctx)
{
    OQS_KEM *kem;
    
    /* Initialize Kyber768 */
    kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        pr_err("Failed to initialize Kyber768\n");
        return -ENOMEM;
    }
    
    ctx->kyber768_kem = kem;
    pr_info("Kyber768 initialized: pk_len=%zu, sk_len=%zu\n",
            kem->length_public_key, kem->length_secret_key);
    
    return 0;
}

/* Generate Kyber keypair */
static int generate_kyber_keypair(struct hardening_quantum_ctx *ctx,
                                  struct hardening_hybrid_key *key)
{
    OQS_KEM *kem = ctx->kyber768_kem;
    OQS_STATUS status;
    
    /* Allocate key buffers */
    key->pq_public_key = kmalloc(kem->length_public_key, GFP_KERNEL);
    key->pq_private_key = kmalloc(kem->length_secret_key, GFP_KERNEL);
    
    if (!key->pq_public_key || !key->pq_private_key) {
        kfree(key->pq_public_key);
        kfree(key->pq_private_key);
        return -ENOMEM;
    }
    
    /* Generate keypair */
    status = OQS_KEM_keypair(kem, key->pq_public_key, key->pq_private_key);
    if (status != OQS_SUCCESS) {
        pr_err("Kyber keypair generation failed\n");
        kfree(key->pq_public_key);
        kfree(key->pq_private_key);
        return -EIO;
    }
    
    key->pq_public_key_len = kem->length_public_key;
    key->pq_private_key_len = kem->length_secret_key;
    key->pq_algo = HARDENING_PQ_KYBER768;
    
    return 0;
}
```

### 6. Makefile Updates

```makefile
# security/hardening/Makefile
hardening-$(CONFIG_SECURITY_HARDENING_QUANTUM) += quantum.o \
    liboqs-kernel/kem/kyber/kyber768.o \
    liboqs-kernel/kem/kyber/kyber1024.o \
    liboqs-kernel/sig/dilithium/dilithium3.o \
    liboqs-kernel/sig/dilithium/dilithium5.o \
    liboqs-kernel/common/rand.o

ccflags-y += -I$(src)/liboqs-kernel/include
```

### 7. Testing Integration

```c
/* Test real Kyber operations */
static int test_kyber_kem(void)
{
    struct hardening_quantum_ctx ctx;
    struct hardening_hybrid_key key;
    uint8_t ciphertext[KYBER_CIPHERTEXT_BYTES];
    uint8_t shared_secret1[32], shared_secret2[32];
    int ret;
    
    /* Initialize */
    ret = init_kyber(&ctx);
    if (ret < 0)
        return ret;
    
    /* Generate keypair */
    ret = generate_kyber_keypair(&ctx, &key);
    if (ret < 0)
        return ret;
    
    /* Encapsulate */
    ret = OQS_KEM_encaps(ctx.kyber768_kem, ciphertext, 
                         shared_secret1, key.pq_public_key);
    if (ret != OQS_SUCCESS)
        return -EIO;
    
    /* Decapsulate */
    ret = OQS_KEM_decaps(ctx.kyber768_kem, shared_secret2,
                         ciphertext, key.pq_private_key);
    if (ret != OQS_SUCCESS)
        return -EIO;
    
    /* Verify shared secrets match */
    if (crypto_memcmp(shared_secret1, shared_secret2, 32) != 0) {
        pr_err("KEM test failed: shared secrets don't match\n");
        return -EINVAL;
    }
    
    pr_info("Kyber KEM test successful\n");
    return 0;
}
```

## Performance Optimizations

1. **Use kernel crypto accelerators** where available
2. **Implement assembly optimizations** for critical paths
3. **Cache frequently used values** (e.g., precomputed tables)
4. **Minimize memory allocations** in hot paths

## Security Considerations

1. **Constant-time operations** - Ensure no timing leaks
2. **Secure memory wiping** - Use crypto_memzero()
3. **Stack usage** - Monitor and minimize (kernel stack is limited)
4. **Side-channel protection** - Implement blinding where needed

## Build Configuration

Add to kernel config:
```
CONFIG_SECURITY_HARDENING_QUANTUM_LIBOQS=y
```

## Verification

After integration, verify:
1. **Correctness** - Test vectors pass
2. **Performance** - Acceptable overhead
3. **Security** - No information leaks
4. **Stability** - No kernel panics/oops

## References

- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Linux Kernel Crypto API](https://www.kernel.org/doc/html/latest/crypto/)