/* SPDX-License-Identifier: MIT */
/*
 * Open Quantum Safe (liboqs) - Kernel Space Wrapper
 *
 * This provides kernel-compatible wrappers for liboqs functions
 */

#ifndef _OQS_KERNEL_H
#define _OQS_KERNEL_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <crypto/hash.h>

/* Status codes */
typedef enum {
	OQS_SUCCESS = 0,
	OQS_ERROR = -1,
	OQS_EXTERNAL_LIB_ERROR = -2,
} OQS_STATUS;

/* Memory management wrappers for kernel space */
#define OQS_MEM_malloc(size) \
	kmalloc(size, GFP_KERNEL)

#define OQS_MEM_calloc(num, size) \
	kcalloc(num, size, GFP_KERNEL)

#define OQS_MEM_realloc(ptr, size) \
	krealloc(ptr, size, GFP_KERNEL)

#define OQS_MEM_free(ptr) \
	kfree(ptr)

#define OQS_MEM_secure_free(ptr, size) \
	do { \
		if (ptr) { \
			memzero_explicit(ptr, size); \
			kfree(ptr); \
		} \
	} while (0)

/* String operations */
#define OQS_MEM_memcpy(dest, src, size) \
	memcpy(dest, src, size)

#define OQS_MEM_memmove(dest, src, size) \
	memmove(dest, src, size)

#define OQS_MEM_memcmp(a, b, size) \
	crypto_memcmp(a, b, size)

#define OQS_MEM_memset(ptr, val, size) \
	memset(ptr, val, size)

#define OQS_MEM_secure_memzero(ptr, size) \
	memzero_explicit(ptr, size)

/* Random number generation using kernel RNG */
static inline void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read)
{
	get_random_bytes(random_array, bytes_to_read);
}

/* CPU feature detection */
#define OQS_CPU_has_extension(ext) 0  /* Simplified for now */

/* Logging */
#define OQS_PRINT_ERROR(fmt, ...) \
	pr_err("liboqs: " fmt "\n", ##__VA_ARGS__)

#define OQS_PRINT_WARNING(fmt, ...) \
	pr_warn("liboqs: " fmt "\n", ##__VA_ARGS__)

#define OQS_PRINT_INFO(fmt, ...) \
	pr_info("liboqs: " fmt "\n", ##__VA_ARGS__)

/* Algorithm identifiers */
#define OQS_KEM_alg_kyber_512 "Kyber512"
#define OQS_KEM_alg_kyber_768 "Kyber768"
#define OQS_KEM_alg_kyber_1024 "Kyber1024"

#define OQS_SIG_alg_dilithium_2 "Dilithium2"
#define OQS_SIG_alg_dilithium_3 "Dilithium3"
#define OQS_SIG_alg_dilithium_5 "Dilithium5"

/* KEM structure */
typedef struct OQS_KEM {
	const char *method_name;
	const char *alg_version;
	
	uint8_t claimed_nist_level;
	bool ind_cca;
	
	size_t length_public_key;
	size_t length_secret_key;
	size_t length_ciphertext;
	size_t length_shared_secret;
	
	/* Function pointers */
	OQS_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
	OQS_STATUS (*encaps)(uint8_t *ciphertext, uint8_t *shared_secret,
			     const uint8_t *public_key);
	OQS_STATUS (*decaps)(uint8_t *shared_secret, const uint8_t *ciphertext,
			     const uint8_t *secret_key);
	
	/* Private implementation data */
	void *priv;
} OQS_KEM;

/* Signature structure */
typedef struct OQS_SIG {
	const char *method_name;
	const char *alg_version;
	
	uint8_t claimed_nist_level;
	bool euf_cma;
	
	size_t length_public_key;
	size_t length_secret_key;
	size_t length_signature;
	
	/* Function pointers */
	OQS_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
	OQS_STATUS (*sign)(uint8_t *signature, size_t *signature_len,
			   const uint8_t *message, size_t message_len,
			   const uint8_t *secret_key);
	OQS_STATUS (*verify)(const uint8_t *message, size_t message_len,
			     const uint8_t *signature, size_t signature_len,
			     const uint8_t *public_key);
	
	/* Private implementation data */
	void *priv;
} OQS_SIG;

/* KEM functions */
OQS_KEM *OQS_KEM_new(const char *method_name);
void OQS_KEM_free(OQS_KEM *kem);
OQS_STATUS OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key,
			   uint8_t *secret_key);
OQS_STATUS OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext,
			  uint8_t *shared_secret, const uint8_t *public_key);
OQS_STATUS OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret,
			  const uint8_t *ciphertext, const uint8_t *secret_key);

/* Signature functions */
OQS_SIG *OQS_SIG_new(const char *method_name);
void OQS_SIG_free(OQS_SIG *sig);
OQS_STATUS OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key,
			   uint8_t *secret_key);
OQS_STATUS OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature,
			size_t *signature_len, const uint8_t *message,
			size_t message_len, const uint8_t *secret_key);
OQS_STATUS OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message,
			  size_t message_len, const uint8_t *signature,
			  size_t signature_len, const uint8_t *public_key);

/* Common utilities */
void OQS_init(void);
void OQS_destroy(void);
const char *OQS_version(void);

/* SHA3 utilities (use kernel crypto) */
void OQS_SHA3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void OQS_SHA3_512(uint8_t *output, const uint8_t *input, size_t inlen);
void OQS_SHAKE128(uint8_t *output, size_t outlen, const uint8_t *input,
		  size_t inlen);
void OQS_SHAKE256(uint8_t *output, size_t outlen, const uint8_t *input,
		  size_t inlen);

#endif /* _OQS_KERNEL_H */